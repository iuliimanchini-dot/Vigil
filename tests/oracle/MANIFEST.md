# Oracle Corpus — Ground Truth Manifest

A reusable regression fixture for the cortex_forensic auditor. Each sample file
contains **minimal, real instances** of a known problem class, marked on the
offending line with `# EXPECT: <tag>`. `clean_control.py` is the idiomatic
counterpart and **must produce zero findings** (false-positive control).

**Tags are this corpus's own labels.** The reviewer maps each tag to the
auditor's real `check_id`(s) and measures recall by running the audit. A
suggested tag → check_id mapping is given at the bottom.

## How the corpus was designed (so the reviewer can trust the samples)

Every sample was written against the **exact detection predicates** read from
the auditor source (not from names or docs). Load-bearing facts that shaped the
samples — all **Verified** by reading source and/or replicating the predicate:

- **File naming.** Files are named `sample_*.py` / `clean_control.py`, NOT
  `test_*`. Most per-file checks skip basenames starting with `test_` /
  `conftest` (e.g. [exception_boundary.py:63](../../cortex_forensic/gate_checks/forensic_clusters/exception_boundary.py),
  [data_quality.py:48](../../cortex_forensic/gate_checks/forensic_clusters/data_quality.py)),
  and `is_test_file` matches Python patterns `("test_", "_test.py")`
  ([language_profiles.py:60](../../cortex_forensic/language_profiles.py)). The
  directory `tests/` does **not** match `test_`, so these files are treated as
  ordinary source and the content checks run.
- **SQL injection** (cluster 12, `security_scan`) is **AST-based**: the dynamic
  string must be the first arg of `.execute/.executemany/.executescript/.query/.raw`,
  the literal template must contain real SQL-clause structure
  (`SELECT … FROM \w`, `UPDATE … SET`, `DELETE FROM`, …), be ≥20 chars, and (for
  concat) have a non-literal operand
  ([edit_mutation.py:166-305](../../cortex_forensic/gate_checks/forensic_clusters/edit_mutation.py)).
  All four SQLi samples use `SELECT * FROM <table> WHERE id=<interp>` so the
  structure regex matches. Verified by replicating the AST predicate: hits on
  lines 23, 28, 33, 38.
- **eval/exec/os.system/pickle/yaml.load** fire on genuine AST `Call` nodes
  ([edit_mutation.py:344-378](../../cortex_forensic/gate_checks/forensic_clusters/edit_mutation.py)).
  `shell=True` fires only when the callee is a subprocess launcher
  (`run/Popen/call/...`) ([edit_mutation.py:309-407](../../cortex_forensic/gate_checks/forensic_clusters/edit_mutation.py)).
  Verified: hits on 51, 55, 59, 63, 67, 71.
- **missing_await** (cluster 42) flags only an un-awaited call to a same-module
  `async def` **from inside another async function**; module-level and
  sync-enclosing calls are skipped
  ([async_quality.py:735-748](../../cortex_forensic/gate_checks/forensic_clusters/async_quality.py)).
  `consume()` awaits `warm_up()` (so it is not itself "pointless async") and
  leaves `load_rows()` un-awaited.
- **Size/complexity** thresholds: `size.function_too_large` at ≥120 lines,
  `size.nesting_too_high` at nesting depth ≥6
  ([size_complexity_checks.py:58-61,182,218](../../cortex_forensic/gate_checks/size_complexity_checks.py)).
  `oversized_pipeline` was generated at 133 lines; `deeply_nested` reaches
  `max_nesting_depth == 6` (verified with the real
  [common.py:225 `max_nesting_depth`](../../cortex_forensic/gate_checks/common.py) logic).
- **No collateral findings.** Each sample file was scanned (replicating the
  detector predicates) to confirm no *unintended* extra hits: no accidental
  4-line duplicate windows, no stray magic numbers in the generated structure
  file, and `clean_control.py` is silent across every mirrored detector.

---

## sample_security.py  (9 samples)

| Line | Tag | Construct | Confidence |
|---|---|---|---|
| 23 | `sqli` | `cur.execute("SELECT * FROM users WHERE id=" + uid)` (concat) | High |
| 28 | `sqli` | `cur.execute(f"SELECT * FROM users WHERE id={uid}")` (f-string) | High |
| 33 | `sqli` | `cur.execute("SELECT * FROM accounts WHERE id=%s" % uid)` (%-format) | High |
| 38 | `sqli` | `cur.execute("SELECT * FROM members WHERE id={}".format(uid))` (.format) | High |
| 47 | `secret` | `SESSION_TOKEN = "<token-shaped dummy>"` | High |
| 51 | `eval_exec` | `eval(user_input)` | High |
| 55 | `eval_exec` | `exec(user_code)` | High |
| 59 | `shell` | `os.system(cmd)` | High |
| 63 | `shell` | `subprocess.run(cmd, shell=True)` | High |
| 67 | `unsafe_deser` | `pickle.loads(raw_bytes)` | High |
| 71 | `unsafe_deser` | `yaml.load(raw_text)` (no SafeLoader) | High |

> **Tag count note:** 11 marked lines covering 9 *classes* (sqli ×4,
> eval_exec ×2, shell ×2, unsafe_deser ×2, secret ×1).

**Secret value — important for the reviewer.** The prompt asked for a `FAKE_`
prefix to dodge commit secret-hooks, but the auditor's secrets check
([code_style.py:73](../../cortex_forensic/gate_checks/forensic_clusters/code_style.py))
**skips any line containing** `example/placeholder/xxx/changeme/your_/test_key/<your/`**fake**.
A line literally containing "fake" would be **suppressed** and never detected.
To satisfy both constraints the value is a synthetic, token-shaped dummy
(`ZmFrZW…`, base64 of "fakedummysecret01value") that:
(a) matches the generic `token = "[A-Za-z0-9+/=]{16,}"` rule,
(b) contains **no** skip-word in the line text (verified: not suppressed), and
(c) is **not** a real provider key format (`ghp_`/`sk-`/`AKIA`/JWT), so commit
secret-scanners should not flag it. It is obviously not a live credential.

`eval/exec/os.system/shell=True` may *also* be reported by the boundary
cluster ([exception_boundary.py:198-209](../../cortex_forensic/gate_checks/forensic_clusters/exception_boundary.py))
under `boundary_validation_scan` — i.e. some lines can yield two findings from
two clusters. That is correct behavior, not a duplicate sample.

---

## sample_quality.py  (12 samples)

| Line | Tag | Construct | Confidence |
|---|---|---|---|
| 8 | `unused_import` | `import json` (never used) | High |
| 14 | `mutable_default` | `def append_item(item, bucket=[])` | High |
| 20 | `resource_leak` | `handle = open(path)` (no `with`) | High |
| 28 | `broad_swallow` | `except Exception:` then `pass` | High |
| 35 | `broad_swallow` | `except Exception:` then log-only, no reraise | High |
| 42 | `bare_except` | `except:` then `pass` | High |
| 46 | `dead_code` | unused private `_never_called()` | **UNCERTAIN** (see below) |
| 52 | `magic_number` | `if elapsed_seconds > 86400:` | High |
| 58 | `todo` | `# TODO: handle empty input …` | High |
| 63 | `debug_print` | `print("DEBUG", x)` | High |
| 69 | `commented_code` | 5-line commented-out block (lines 69–73) | Medium |
| 79 | `naive_tz` | `datetime.now()` (no tz) | High |
| 83 | `path_concat` | `base_dir + "/" + name + ".log"` | High |

> **`broad_swallow` maps to two different check_ids.** Line 28 (`pass`) is caught
> by the *swallowed-exception* check (cluster 31, `exception_swallow_scan`,
> [exception_boundary.py:87-104](../../cortex_forensic/gate_checks/forensic_clusters/exception_boundary.py)).
> Line 35 (log-only, no reraise) is **not** "swallowed" by cluster 31's
> definition; it is caught by the *broad-catch-no-reraise* check (cluster 39,
> `broad_catch_scan`, [async_quality.py:61-89](../../cortex_forensic/gate_checks/forensic_clusters/async_quality.py)).
> Both are genuine instances of "broad exception handling that hides errors";
> the reviewer may score them under either/both check_ids.

> **`bare_except` (line 42)** is reported by the **same** cluster-31 check as a
> separate branch (`re.match(r'^except\s*:')`); its `check_id` is also
> `exception_swallow_scan` but the finding title is `[exception_swallowing]`.

---

## sample_async_api.py  (2 samples)

| Line | Tag | Construct | Confidence |
|---|---|---|---|
| 31 | `missing_await` | `rows = load_rows()` (async call, not awaited, inside `async def consume`) | High |
| 36 | `unchecked_response` | `resp = requests.get(url)` then `.json()` with no status check | High |

---

## sample_structure.py  (3 samples — generated)

| Line | Tag | Construct | Confidence |
|---|---|---|---|
| 30 | `size_function` | `oversized_pipeline` — 133-line function (≥120 revise threshold) | High |
| 165 | `nesting` | `deeply_nested` — block nesting depth 6 (≥6 revise threshold) | High |
| 177 / 186 | `duplication` | `route_alpha` / `route_beta` — identical 6-line bodies | High (intra-file C45) / Medium (cross-file) |

> **Duplication detail.** The intra-file near-duplicate check
> (cluster 45 `assess_near_duplicate_code`,
> [data_quality.py:133](../../cortex_forensic/gate_checks/forensic_clusters/data_quality.py))
> fires on the shared 6-line body (≥4-line sliding window, ≥4 lines apart —
> verified). The cross-file function-dup check
> ([duplication_checks.py](../../cortex_forensic/gate_checks/duplication_checks.py))
> hashes whole functions but **skips `is_test_file`** (these files are not test
> files) and is gated by touched-file-set size (full-scan clears the touched
> hashes); so the cross-file `duplication.normalized_function` finding is
> **not guaranteed**. The duplication class is reliably covered by C45.
> Nesting depth is measured **per-file** (max over the file); `deeply_nested`
> is the only deep region, so exactly one nesting finding is expected.

---

## clean_control.py  (0 samples — false-positive control)

Idiomatic, safe counterparts. **Expected findings: ZERO.** Verified silent
against mirrored detectors for: secrets, hardcoded paths, magic numbers,
TODO/FIXME, shadowed builtins, unchecked response, naive datetime, path concat,
mutable defaults, resource leaks, debug prints, broad except, naming
consistency.

Constructs demonstrated:
- Parametrised query `cur.execute("SELECT * FROM users WHERE id = ?", (uid,))`.
- `with open(path, encoding="utf-8") as handle:` (context-managed).
- `except OSError:` … `raise` (specific type, re-raised).
- `datetime.now(tz=timezone.utc)` (timezone-aware).
- `os.path.join(base_dir, name + ".log")` (path joining).
- `SECONDS_PER_DAY = 86400` named constant used as `elapsed > SECONDS_PER_DAY`.
- `def append_item(item, bucket=None)` with `if bucket is None: bucket = []`.
- `response = requests.get(...); response.raise_for_status()` (status checked).

> If the auditor emits **any** finding on `clean_control.py`, that is a
> false positive worth investigating. The most likely FP risk is the timezone
> import or the `requests` call, both of which are written in the
> auditor-recommended safe form.

---

## Ground-truth summary (tag → count of marked lines)

| Tag | Count | Class |
|---|---|---|
| `sqli` | 4 | security |
| `secret` | 1 | security |
| `eval_exec` | 2 | security |
| `shell` | 2 | security |
| `unsafe_deser` | 2 | security |
| `unused_import` | 1 | quality |
| `mutable_default` | 1 | quality |
| `resource_leak` | 1 | quality |
| `broad_swallow` | 2 | quality |
| `bare_except` | 1 | quality |
| `dead_code` | 1 | quality |
| `magic_number` | 1 | quality |
| `todo` | 1 | quality |
| `debug_print` | 1 | quality |
| `commented_code` | 1 | quality |
| `naive_tz` | 1 | quality |
| `path_concat` | 1 | quality |
| `missing_await` | 1 | async/api |
| `unchecked_response` | 1 | async/api |
| `size_function` | 1 | structure |
| `nesting` | 1 | structure |
| `duplication` | 1 | structure (2 marked lines, one duplicated region) |
| **TOTAL** | **29 marked lines / 22 distinct classes** | |

**Counts by category:** security 11 lines (5 classes) · quality 13 lines
(12 classes) · async/api 2 lines (2 classes) · structure 4 lines (3 classes).

---

## Samples flagged UNCERTAIN-to-detect (honest)

1. **`dead_code` (sample_quality.py:46).** `assess_dead_code`
   ([dead_code.py:55](../../cortex_forensic/gate_checks/forensic_clusters/dead_code.py))
   consumes a `DeadCodeItem` list built upstream by **cross-file reference
   analysis** with classification heuristics (`__all__`, recency, framework
   decorators, "standalone" name markers, referenced-anywhere). It fires only
   when the item is classified `dead_code` / `likely_forgotten_wiring`. Whether
   `_never_called` reaches that state depends on the orchestrator running that
   cross-file pass over `tests/oracle/` and on the function being referenced
   nowhere. Plausible but **not guaranteed** in a static directory scan.
2. **`commented_code` (sample_quality.py:69).** Confidence Medium. The block
   satisfies the documented conditions (≥3 lines, ≥2 code-indicator lines,
   ≤10 lines, not a docstring, not in the first 4 lines), but the detector uses
   a comment-body code-indicator heuristic
   ([async_quality.py:336-480](../../cortex_forensic/gate_checks/forensic_clusters/async_quality.py))
   that could classify differently than predicted.
3. **`duplication` cross-file flavor (sample_structure.py:177/186).** The
   intra-file C45 finding is High confidence; the **cross-file**
   `duplication.normalized_function` finding is **not guaranteed** because that
   check skips test files and is gated by the touched-file-set size. Treat the
   duplication class as covered by C45.
4. **General gating caveat.** If the auditor runs in a mode that only inspects
   git-changed files against a baseline, these files must be **committed** to be
   seen (they are, by this corpus's commit). A few checks are runtime-only and
   are gated **off** in a pure static scan (e.g. success-proof / config-applied
   / mutation-verified clusters) — none of the tags above depend on those.

---

## Suggested tag → check_id mapping (reviewer convenience; verify against runner)

| Tag | Likely `check_id`(s) |
|---|---|
| `sqli` | `security_scan` (also possibly `boundary_validation_scan`) |
| `secret` | `secrets_scan` |
| `eval_exec` | `security_scan` (also possibly `boundary_validation_scan`) |
| `shell` | `security_scan` (also possibly `boundary_validation_scan`) |
| `unsafe_deser` | `security_scan` |
| `unused_import` | `unused_import_scan` |
| `mutable_default` | `mutable_default_scan` |
| `resource_leak` | `resource_leak_scan` |
| `broad_swallow` | `exception_swallow_scan` (line 28) / `broad_catch_scan` (line 35) |
| `bare_except` | `exception_swallow_scan` |
| `dead_code` | `dead_code_scan` |
| `magic_number` | `magic_number_scan` |
| `todo` | `todo_scan` |
| `debug_print` | `debug_print_scan` |
| `commented_code` | `commented_code_scan` |
| `naive_tz` | `timezone_scan` |
| `path_concat` | `path_concat_scan` |
| `missing_await` | `missing_await_scan` |
| `unchecked_response` | `response_status_scan` |
| `size_function` | `size.function_too_large` |
| `nesting` | `size.nesting_too_high` |
| `duplication` | `duplicate_scan` (C45 intra-file); maybe `duplication.normalized_function` |
