"""P1: ML/NN gate pack — recall (positive fires) + precision (negative silent).

Each check is exercised on a minimal positive fixture (must fire its check_id)
and a minimal negative fixture (must stay silent), plus one integration test
through the public run_ml_checks runner.
"""
from __future__ import annotations

import ast

from vigil_forensic.gate_checks.ml_checks import (
    _check_lookahead_shift,
    _check_missing_seed,
    _check_nondeterministic_split,
    _check_scaler_fit_on_test,
    run_ml_checks,
)


def _ids(fn, src: str) -> set[str]:
    return {f.check_id for f in fn("f.py", ast.parse(src))}


# 1. look-ahead via negative shift -------------------------------------------
def test_lookahead_fires_on_negative_shift():
    assert "ml.lookahead_negative_shift" in _ids(_check_lookahead_shift, "y = df['c'].shift(-1)\n")


def test_lookahead_fires_on_periods_kwarg():
    assert "ml.lookahead_negative_shift" in _ids(_check_lookahead_shift, "y = s.shift(periods=-3)\n")


def test_lookahead_silent_on_positive_shift():
    assert _ids(_check_lookahead_shift, "y = df['c'].shift(1)\n") == set()


# 2. non-deterministic split -------------------------------------------------
def test_split_fires_without_random_state():
    assert "ml.nondeterministic_split" in _ids(
        _check_nondeterministic_split, "a, b = train_test_split(X, y)\n"
    )


def test_split_silent_with_random_state():
    assert _ids(
        _check_nondeterministic_split, "a, b = train_test_split(X, y, random_state=42)\n"
    ) == set()


# 3. scaler fit on test/val (leakage) ----------------------------------------
def test_scaler_fires_on_test_arg():
    assert "ml.scaler_fit_on_test" in _ids(_check_scaler_fit_on_test, "scaler.fit(X_test)\n")


def test_scaler_fires_on_fit_transform_val():
    assert "ml.scaler_fit_on_test" in _ids(_check_scaler_fit_on_test, "z = sc.fit_transform(X_val)\n")


def test_scaler_silent_on_train():
    assert _ids(_check_scaler_fit_on_test, "scaler.fit(X_train)\n") == set()


# 4. missing random seed -----------------------------------------------------
def test_seed_fires_when_rng_unseeded():
    assert "ml.missing_random_seed" in _ids(
        _check_missing_seed, "import numpy as np\nz = np.random.rand(10)\n"
    )


def test_seed_silent_when_seeded():
    assert _ids(
        _check_missing_seed,
        "import numpy as np\nnp.random.seed(0)\nz = np.random.rand(10)\n",
    ) == set()


def test_seed_silent_when_no_rng():
    assert _ids(_check_missing_seed, "x = 1 + 2\n") == set()


# integration through the public runner --------------------------------------
def test_runner_integration_fires():
    class _Snap:
        def __init__(self, t):
            self.text = t

    class _Ctx:
        file_snapshots = {"bad_model.py": _Snap("y = df['c'].shift(-1)\n")}

    res = run_ml_checks(_Ctx())
    ids = {f.check_id for f in res.findings}
    assert "ml.lookahead_negative_shift" in ids


def test_runner_integration_clean_silent():
    class _Snap:
        def __init__(self, t):
            self.text = t

    class _Ctx:
        file_snapshots = {"clean.py": _Snap("def add(a, b):\n    return a + b\n")}

    res = run_ml_checks(_Ctx())
    assert [f for f in res.findings if str(f.check_id).startswith("ml.")] == []
