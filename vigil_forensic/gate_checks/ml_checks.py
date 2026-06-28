"""ML/NN correctness forensic checks (static AST, Python-only).

Catches machine-learning / quant-trading bugs that generic linters miss and that
are catastrophic in backtests and live trading:

  ml.lookahead_negative_shift  -- .shift(-N): future data leaks into the present row
  ml.nondeterministic_split    -- train_test_split(...) with no random_state
  ml.scaler_fit_on_test        -- .fit()/.fit_transform() on a *_test / *_val array
  ml.missing_random_seed       -- module uses RNG but never seeds it

Pure AST over file snapshots — never executes the model. Conservative by design:
prefers a missed case over a false alarm (these run on any Python repo, most of
which is not ML code).
"""
from __future__ import annotations

import ast
import logging

from vigil_forensic._shared import (
    EvidenceReference,
    GateCategory,
    GateImpact,
    GateSeverity,
    RepairKind,
)
from vigil_forensic.gate_checks.common import build_check_result, build_finding

_log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _negative_int(node: ast.AST) -> int | None:
    """Return the negative int value of *node* if it is a negative int literal."""
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        return -node.operand.value
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
        and node.value < 0
    ):
        return node.value
    return None


def _shift_negative_period(call: ast.Call) -> int | None:
    """If *call* is ``.shift(-N)`` / ``.shift(periods=-N)`` return the negative N."""
    if call.args:
        v = _negative_int(call.args[0])
        if v is not None:
            return v
    for kw in call.keywords:
        if kw.arg == "periods":
            v = _negative_int(kw.value)
            if v is not None:
                return v
    return None


def _arg_name_lower(node: ast.AST) -> str:
    """Best-effort lowercase name of an argument expression (Name or attribute)."""
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return node.value.id.lower()
    return ""


# --------------------------------------------------------------------------
# check 1: look-ahead via negative shift
# --------------------------------------------------------------------------

def _check_lookahead_shift(path: str, tree: ast.AST) -> list:
    findings = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "shift":
            continue
        neg = _shift_negative_period(node)
        if neg is None:
            continue
        ln = int(getattr(node, "lineno", 0) or 0)
        findings.append(build_finding(
            check_id="ml.lookahead_negative_shift",
            category=GateCategory.ML,
            title=f"Negative .shift({neg}) leaks future data in {path}:{ln}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=(
                f".shift({neg}) at {path}:{ln} moves a series BACKWARD, exposing future "
                "values to the current row. This is look-ahead bias: it inflates "
                "backtest/validation metrics and silently fails in live use."
            ),
            recommendation=(
                "Features must only see past data: use a forward (positive) shift, "
                "or if this is target construction, ensure the model never receives "
                "the shifted future column as an input feature."
            ),
            evidence=[EvidenceReference(
                kind="file", path=str(path), detail=f"line:{ln} shift({neg})",
            )],
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action="Replace negative shift with a causal (positive) shift or isolate target alignment.",
            proof_required="No negative .shift() feeds a feature column; backtest uses only past data.",
            allowlist_allowed=True,
        ))
    return findings


# --------------------------------------------------------------------------
# check 2: non-deterministic train_test_split
# --------------------------------------------------------------------------

def _is_named_call(node: ast.Call, name: str) -> bool:
    f = node.func
    return (isinstance(f, ast.Name) and f.id == name) or (
        isinstance(f, ast.Attribute) and f.attr == name
    )


def _check_nondeterministic_split(path: str, tree: ast.AST) -> list:
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_named_call(node, "train_test_split"):
            continue
        has_seed = any(kw.arg == "random_state" for kw in node.keywords)
        if has_seed:
            continue
        ln = int(getattr(node, "lineno", 0) or 0)
        findings.append(build_finding(
            check_id="ml.nondeterministic_split",
            category=GateCategory.ML,
            title=f"train_test_split without random_state in {path}:{ln}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"train_test_split at {path}:{ln} has no random_state. The split is "
                "non-reproducible: every run shuffles differently, so metrics, "
                "hyperparameter choices, and bug reports cannot be reproduced."
            ),
            recommendation="Pass an explicit random_state=<int> for a reproducible split.",
            evidence=[EvidenceReference(
                kind="file", path=str(path), detail=f"line:{ln}",
            )],
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action="Add random_state=<int> to train_test_split.",
            proof_required="train_test_split carries an explicit random_state.",
            allowlist_allowed=True,
        ))
    return findings


# --------------------------------------------------------------------------
# check 3: scaler / transformer fit on test or validation data (leakage)
# --------------------------------------------------------------------------

_FIT_METHODS = frozenset({"fit", "fit_transform"})
_LEAK_TOKENS = ("test", "val", "valid", "holdout", "oot")


def _check_scaler_fit_on_test(path: str, tree: ast.AST) -> list:
    findings = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _FIT_METHODS or not node.args:
            continue
        argname = _arg_name_lower(node.args[0])
        if not argname:
            continue
        # token must appear as a word-ish piece (x_test, test_x, X_val) — substring
        # is acceptable here because these names are conventional and specific.
        if not any(tok in argname for tok in _LEAK_TOKENS):
            continue
        ln = int(getattr(node, "lineno", 0) or 0)
        findings.append(build_finding(
            check_id="ml.scaler_fit_on_test",
            category=GateCategory.ML,
            title=f".{node.func.attr}() on '{argname}' (eval data) in {path}:{ln}",
            severity=GateSeverity.HIGH,
            impact=GateImpact.REVISE,
            summary=(
                f"{node.func.attr}() is called on '{argname}' at {path}:{ln}. Fitting a "
                "scaler/transformer/model on test or validation data leaks information "
                "from the eval set into training, producing optimistic, invalid metrics."
            ),
            recommendation=(
                "Fit transforms ONLY on the training split, then .transform() (not "
                "fit_transform) the test/validation split."
            ),
            evidence=[EvidenceReference(
                kind="file", path=str(path), detail=f"line:{ln} {node.func.attr}({argname})",
            )],
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action="Fit on train only; use transform() on eval data.",
            proof_required="No fit/fit_transform on a *_test/*_val array.",
            allowlist_allowed=True,
        ))
    return findings


# --------------------------------------------------------------------------
# check 4: RNG used but never seeded (non-reproducible)
# --------------------------------------------------------------------------

# Calls that *consume* randomness (attribute chains ending in these), e.g.
# np.random.rand / torch.randn / random.shuffle.
_RNG_CONSUMERS = frozenset({
    "rand", "randn", "randint", "random", "choice", "shuffle", "permutation",
    "normal", "uniform", "standard_normal", "sample", "randperm",
})
# Calls that *seed* an RNG.
_SEED_CALLS = frozenset({"seed", "manual_seed", "manual_seed_all", "set_seed"})


def _attr_chain(node: ast.AST) -> str:
    """Return the dotted attribute chain text for a Call.func (best effort)."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _check_missing_seed(path: str, tree: ast.AST) -> list:
    uses_rng = False
    has_seed = False
    rng_line = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        chain = _attr_chain(node.func)
        leaf = node.func.attr
        if leaf in _SEED_CALLS:
            has_seed = True
        # consumer must be under a random/np.random/torch namespace to avoid
        # flagging unrelated .sample()/.choice() on domain objects.
        if leaf in _RNG_CONSUMERS and (
            "random" in chain or chain.startswith("np.") or chain.startswith("numpy.")
            or chain.startswith("torch") or chain.startswith("tf.")
        ):
            uses_rng = True
            if not rng_line:
                rng_line = int(getattr(node, "lineno", 0) or 0)
    # also count random_state=/seed= kwargs anywhere as "seeded"
    if uses_rng and not has_seed:
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg in ("random_state", "seed"):
                has_seed = True
                break
    if uses_rng and not has_seed:
        return [build_finding(
            check_id="ml.missing_random_seed",
            category=GateCategory.ML,
            title=f"RNG used but never seeded in {path}",
            severity=GateSeverity.MEDIUM,
            impact=GateImpact.REVISE,
            summary=(
                f"{path} consumes randomness (first use at line {rng_line}) but never "
                "sets a seed (np.random.seed / torch.manual_seed / random.seed) and "
                "passes no random_state=. Runs are non-reproducible — results, bugs, "
                "and metrics cannot be replicated."
            ),
            recommendation="Seed all RNGs at module/entrypoint start (np.random.seed, torch.manual_seed, random.seed) or pass random_state=.",
            evidence=[EvidenceReference(
                kind="file", path=str(path), detail=f"first RNG use line:{rng_line}",
            )],
            repair_kind=RepairKind.FIX_CONTRACT.value,
            executor_action="Seed all random number generators deterministically.",
            proof_required="A seed is set before any RNG consumption in the module.",
            allowlist_allowed=True,
        )]
    return []


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def run_ml_checks(ctx) -> "object":
    """Run all ML/NN correctness checks over the snapshot corpus (static)."""
    findings: list = []
    snapshots = getattr(ctx, "file_snapshots", None) or {}
    for path, snap in snapshots.items():
        if not str(path).endswith(".py"):
            continue
        content = getattr(snap, "text", None)
        if not content:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        findings.extend(_check_lookahead_shift(path, tree))
        findings.extend(_check_nondeterministic_split(path, tree))
        findings.extend(_check_scaler_fit_on_test(path, tree))
        findings.extend(_check_missing_seed(path, tree))
    return build_check_result(
        check_id="ml_checks",
        category=GateCategory.ML,
        findings=findings,
    )
