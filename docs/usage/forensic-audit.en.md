# forensic-audit — User Guide

A static code-quality auditor exposed as an MCP server. You point it at a project, it reads the code with `tree-sitter` / AST, and reports problems. It **never runs your code** — no imports, no test execution, no side effects.

## What it is

`forensic-audit` is a read-only forensic auditor for source code. It parses files into syntax trees and walks them looking for known problem patterns. Because it is pure static analysis, it is safe to run on code you do not trust and on code that you cannot (or do not want to) execute.

Supported languages:

- **Python** — full support (the deepest gates target Python).
- **Go, Java, JavaScript, TypeScript** — partial support via adapters (shallower than Python).

## What it gives you

It detects **22 problem classes** (recall 22/22 on the project test corpus):

- SQL injection (a tainted string passed directly to `.execute()`)
- Hardcoded secrets
- `eval` / `exec`
- `shell=True` / `os.system`
- Unsafe `pickle` / `yaml.load`
- Mutable default arguments
- Resource leaks (`open` without a `with` block)
- Broad / bare `except` that swallows errors
- Dead code (private, unreferenced)
- Unused imports
- Magic numbers
- `TODO` / `FIXME`
- Debug `print`
- Commented-out code
- Naive `datetime`
- Path concatenation
- Missing `await`
- Unchecked HTTP response
- Oversized functions
- Deep nesting
- Near-duplicate code

Output is **summary-first**: by default you get a compact summary (~3k tokens) — counts by severity, counts by `check_id`, and the top findings from the highest severity present. Ask for `view='full'` only when you need the complete, paginated list.

Each finding carries an `exit_code` at the run level:

- `0` — clean
- `1` — HIGH / CRITICAL findings exist
- `2` — error

The output is **deterministic**: the same code produces the same findings across runs.

## When to use

- Before committing or merging a change.
- When you want a second opinion on a codebase's quality and risk surface.
- When auditing third-party or unfamiliar code you would rather not execute.
- As a recall-oriented sweep: it errs toward reporting, so it is good for "show me everything that might be wrong," then you triage.

It is **not** a test runner and **not** a linter replacement for style-only concerns — it focuses on real bugs, security issues, and structural smells.

## How to install and use

Currently this is a **local editable install** (it is not on PyPI yet). It works on the machine where you install it; publishing to PyPI for use on other machines is pending.

From the `cortex-codeintel` repository root:

```bash
pip install -e .   # from the cortex-codeintel repo
claude mcp add forensic-audit -s user -- <abs-path-to-venv-python> -m cortex_mcp.forensic_server
```

Replace `<abs-path-to-venv-python>` with the absolute path to the Python interpreter in your virtual environment, e.g. on Windows:

```
C:\Users\You\path\to\cortex-codeintel\.venv\Scripts\python.exe
```

Once added, the server exposes a **background job + poll** API. The typical flow is:

1. `start_forensic_audit(path)` → returns a `job_id` and the `resolved_path`. Leave `path` empty to auto-detect the project root by walking up from the current directory.
2. `get_forensic_status(job_id)` → poll until `status == "done"` (usually seconds).
3. `get_forensic_results(job_id)` → the compact summary. Read this first.
4. Only if needed: `get_forensic_results(job_id, view='full', severity='HIGH')` or `check_id='...'` to drill into specific findings.

What to expect on real code:

- On a clean small library (e.g. `filelock`, ~14 files) it reports roughly **38 findings**, mostly genuine ones — large file size, broad `except`, unused imports.
- On large projects it produces many findings (it is recall-oriented). **Triage HIGH first.**

The project root is auto-detected when you omit `path`.

## Pros

- **Full 22-class recall** on the test corpus.
- **Low false-positive rate on clean code.**
- **Configurable** — enable, disable, or restrict which gates run (see Tuning).
- **Compact summary** that will not blow your context budget.
- **Cross-platform.**
- **Deterministic** output, stable across runs.

## Cons and limits

Being honest about what it does *not* do:

- **SQL-injection detection is narrow.** It fires only when the tainted string is the **direct** argument of `.execute()`. There is no taint-tracking across variables, so an injection assembled through intermediate variables can be missed.
- **A scan can take ~20s on very large projects** (a per-gate AST walk).
- **The false-positive rate on large codebases has not been verified line by line.** It is recall-oriented, so expect noise on big projects and triage accordingly.
- **Depth is uneven across languages.** Some gates are deepest for Python; Go / Java / JS / TS are shallower.
- It does **not** run your code, so anything that only manifests at runtime is out of scope. (For structural understanding — entry points, who writes what, dependency maps — use the companion `code-map` server.)

## Tuning

Configuration lives under `<project>/.cortex/`.

- **Disable noisy gates** for a project: create `<project>/.cortex/disabled_gates.json` containing a list of gate ids, e.g. `["gate_id", ...]`. Those gates never run.
- **Run only specific gates:** pass `gates="id1,id2"` (comma-separated). Everything else is skipped.
- **Raise the severity floor:** pass `severity="HIGH"` to keep only HIGH / CRITICAL findings.
- **Enable opt-in heuristic gates** (off by default because they are noisy, e.g. `god_object_zones`): name them in `gates=`.
