# cortex-codeintel

Two FastMCP stdio servers for code intelligence, backed by multi-language static analysis cores.

**License:** MIT (see [LICENSE](LICENSE)). Change the copyright holder before any publication.

---

## What it is

`cortex-codeintel` packages three cooperating libraries:

- **`cortex_map_builder`** — structural code mapper. Parses Python (stdlib `ast`) and Go/Java/JS/TS (tree-sitter). Produces typed maps: structural (imports + symbols), data contracts, runtime signals, authority writes, hotspots, refactor boundaries, conflicts, and findings. Output is written to `<project>/.cortex/maps/` as JSON.

- **`cortex_forensic`** — static forensic gate auditor. Runs a suite of 40+ pattern-based checks (broad-except, hallucinations, TOCTOU, security injection, config-safety, contract drift, etc.) against a project directory. Returns structured findings with severity, category, evidence, and fingerprint. Single public function: `run_forensic_audit(project_dir, ...) -> dict`.

- **`cortex_mcp`** — two FastMCP stdio servers (`code-map`, `forensic-audit`) that wrap the above cores behind a **background-job + poll** API. Resource-constrained: max 2 concurrent jobs, cancellable, output paginated/capped at 80 000 chars (~25 k tokens) per page.

---

## Capability matrix

The table below reflects the actual `supports_*` flags and implementation state read from the adapter sources.

| Language | Structural (imports + symbols) | Contracts | Runtime signals | Authority writes |
|----------|-------------------------------|-----------|-----------------|------------------|
| **Python** | yes — stdlib `ast`, fully implemented | flag set; stubs return `[]` (L3+ wiring not done) | flag set; stubs return `[]` (L3+ wiring not done) | flag set; stubs return `[]` (L3+ wiring not done) |
| **Go** | yes — tree-sitter, fully implemented | yes — structs and interfaces via tree-sitter | yes — `init`, goroutine spawns, package-level `var = call(...)` | yes — `os.WriteFile`, `os.Create`, `.Write`, `.Exec` |
| **Java** | yes — tree-sitter, fully implemented | yes — class/record/interface/enum via tree-sitter | yes — `static {}`, Spring stereotypes, thread/executor spawns | yes — `Files.write`, `.write`/`.append`, `.save`/`.persist`, `new FileWriter` |
| **JavaScript** | yes — tree-sitter, fully implemented | not supported (`supports_contracts = False`) | yes — timer, event listener, top-level effects | yes — write patterns via tree-sitter |
| **TypeScript** | yes — tree-sitter, fully implemented | yes — via regex (contracts, interfaces, zod schemas) | yes — via regex | yes — via tree-sitter |

**Forensic gates:** language-aware; runs on all five languages where applicable. The gate framework uses `cortex_map_builder` sources internally.

> **Note on the Python row.** "Authority writes — stubs return `[]`" refers to the *adapter* (`PythonAdapter.extract_writer_calls`). Real Python write detection lives in `authority_builder.py` (stdlib `ast`): `.write_text` / `.write_bytes` / `.save` / `os.replace`, plus `open(..., "w"/"a"/"x"/"+")` and `json.dump(...)`. Reads (`open(p)` / `open(p, "r")` / `.read_text()` / `json.load` / `json.dumps`) are not writes.

### Authority map works out-of-the-box (no seed required)

The authority map (`cortex_map_builder/authority_builder.py`) is useful on any project **without configuration**. With **no** `<project>/.cortex/map_seeds/authority_domains.json`, every discovered write site is auto-surfaced as an *inferred* per-writer `AuthorityDomain` (`status="inferred"`, `source="static_scan"`, modest confidence). Each entry names the writer file (`canonical_owner`) and lists its resolved write targets + operation kinds, so the map is immediately actionable. A pure read never produces an entry.

Providing a seed switches to the structured behaviour: domains carry `target_file_patterns`, writers are attributed by AST-resolved target match, and seed entries are `status="observed"`. With a seed present, the per-writer auto-surfacing is **not** added (no double-surfacing).

Known limitation: write sites whose target is unresolvable and which use idioms outside the detected set — notably the atomic-write trio `os.fdopen(fd, "w")` + `fh.write(...)` + `os.replace(tmp, str(path))` — are not detected, so a file that *only* writes that way (e.g. `cortex_map_builder/map_storage.py`) will not surface. This is a discovery-layer limitation, independent of the seed behaviour.

### Runtime map surfaces entrypoints out-of-the-box (no seed required)

The runtime map (`cortex_map_builder/runtime_builder.py`) surfaces real entrypoints on any project **without configuration**. With **no** `<project>/.cortex/map_seeds/runtime_seed.json`, the Python AST scanner (`_runtime_ast._RuntimeVisitor`) emits inferred `RuntimeNode` entries (`status="inferred"`, `source="static_scan"`, evidence pointing at `file:line`) for:

- `if __name__ == "__main__":` blocks (`kind="main_entrypoint"`); the invoked entry functions are recorded in `calls`;
- the module-level function(s) invoked from that block (`kind="entry_function"`);
- async entrypoints (`asyncio.run(...)` in a `__main__` block) — tagged `async_entrypoint`.

Adapter-provided runtime signals (Go `init`/goroutine, Java static-block/Spring/thread, JS timer/listener/top-level effect) already surface without a seed via `collect_adapter_runtime_nodes`; this change adds the Python `__main__`/entry-function path that was previously missing.

Precision guard: an ordinary helper function or a plain import is **not** an entrypoint. A `def main(): ...` *without* a `__main__` guard is just a function and does **not** produce a `main_entrypoint` node. Providing a seed keeps the existing behaviour — seed nodes are `status="canonical"` and win on name conflicts, so the same node is never double-surfaced; auto-discovered nodes augment the seed.

Known limitation: entrypoints exposed only via packaging (`console_scripts` / `[project.scripts]`) without an in-file `__main__` guard — e.g. `cortex_map_builder/cli_entry.py` — are not surfaced by the static scan (there is no in-source signal to key on). Background tasks/routes are detected only inside init-style function bodies (`__init__`/`bootstrap`/`setup`/`startup`/`start`/`initialize`/`init`), per the existing visitor scope.

---

## Install

```bash
pip install -e .
```

**Hard dependencies** (pulled automatically by pip):
- `tree-sitter >= 0.25, < 0.26`
- `tree-sitter-language-pack >= 1.10`
- `filelock >= 3.12, < 4`
- `mcp >= 1.0`

**Dev extras** (adds pytest):
```bash
pip install -e ".[dev]"
```

---

## Register in Claude Code

### Option A — `claude mcp add` (stdio, recommended)

```bash
claude mcp add code-map -- cortex-map-mcp
claude mcp add forensic-audit -- cortex-forensic-mcp
```

Both commands are entry points installed by `pip install -e .`.

### Option B — `.mcp.json` (project file)

```json
{
  "mcpServers": {
    "code-map": {
      "type": "stdio",
      "command": "cortex-map-mcp",
      "args": []
    },
    "forensic-audit": {
      "type": "stdio",
      "command": "cortex-forensic-mcp",
      "args": []
    }
  }
}
```

Place `.mcp.json` in the project root or in `~/.claude/`.

---

## Tool list

### Server: `code-map`

| Tool | Description |
|------|-------------|
| `start_code_map` | Start a background map-build job. Args: `path` (absolute project root), `map` (`"all"` or specific map name). Returns `job_id`. |
| `get_code_map_status` | Poll job status. Args: `job_id`. Returns `status`: `running / done / error / cancelled / not_found`. |
| `get_code_map_results` | Retrieve completed results (paginated). Args: `job_id`, `page` (0-based), `page_size_chars`. Returns structured maps payload. |
| `load_code_map_by_path` | Load previously built maps from disk without a job. Args: `path`, `page`, `page_size_chars`. |
| `cancel_code_map` | Cancel a running job. Args: `job_id`. |

### Server: `forensic-audit`

| Tool | Description |
|------|-------------|
| `start_forensic_audit` | Start a background forensic audit. Args: `path`, `gates` (comma-separated check_ids or empty for all), `severity` (`LOW / MEDIUM / HIGH / CRITICAL`), `all_languages`. Returns `job_id`. |
| `get_forensic_status` | Poll job status. Args: `job_id`. |
| `get_forensic_results` | Retrieve results (paginated + capped). Args: `job_id`, `page`, `page_size_chars`, `max_findings` (default 200). Returns `exit_code`, `findings`, `meta`, `errors`. |
| `cancel_forensic_audit` | Cancel a running audit. Args: `job_id`. |

---

## Usage pattern: the poll workflow

Both servers use the same start → poll → retrieve pattern. Push delivery is not used here (see note below).

```python
# Example: map build via MCP tool calls (pseudocode showing the call sequence)

# 1. Start the job
result = call_tool("start_code_map", {"path": "/path/to/project", "map": "all"})
job_id = result["job_id"]

if result["status"] == "busy":
    # Server is at max concurrent jobs; wait and retry start_code_map
    ...

# 2. Poll until done
while True:
    s = call_tool("get_code_map_status", {"job_id": job_id})
    if s["status"] in ("done", "error", "cancelled"):
        break
    time.sleep(2)

# 3. Retrieve results (paginated if large)
page = 0
while True:
    r = call_tool("get_code_map_results", {"job_id": job_id, "page": page})
    process(r["payload"])           # JSON string
    if not r["truncated"]:
        break
    page += 1
```

The same three-step pattern applies to `forensic-audit`: `start_forensic_audit` → `get_forensic_status` → `get_forensic_results`.

---

## Resource and concurrency guarantees

- **Max 2 concurrent jobs** per server process (enforced by `_jobs.JobRegistry`).
- **`forensic-audit` additionally uses `workers=1`** internally inside `run_forensic_audit`.
- Jobs are **cancellable** at any time via `cancel_code_map` / `cancel_forensic_audit`.
- Output is **paginated and capped**: each results page is at most 80 000 chars (~25 k tokens); findings are capped at 200 per `get_forensic_results` call by default.
- Map analysis is **incremental**: tree-sitter parses file-by-file; `run_map_build` has a 300 s time budget and writes each map independently — the server will not hang the host process.

---

## Job persistence (results survive a restart)

Completed job results are **disk-backed**, so a finished audit or map build is
still retrievable after the MCP server process restarts.

- **Where files live.** Each job is persisted under its own project root at
  `<project_dir>/.cortex/cortex_jobs/<job_id>.json` (the `project_dir` is the
  resolved path the `start_*` tool targeted). A small global index keyed by
  `job_id` lives under the user state dir (`~/.cortex/cortex_jobs_index/`) so a
  restarted server — which polls by `job_id` only — can locate the owning
  project. Persistence engages only when a `project_dir` is known; an in-memory
  job started without one keeps the legacy behaviour (lost on exit).
- **Atomic mechanism.** Records are written via `tempfile.mkstemp` + `os.replace`
  under a per-job `filelock.FileLock` — the same atomic pattern as
  `cortex_map_builder.map_storage`. `os.replace` is atomic on POSIX and Windows,
  so a reader never observes a half-written file. The terminal record is written
  to disk **before** the in-memory status flips to terminal, so disk is never
  behind what `get_*_status` reports.
- **Restart / interrupted semantics.** Terminal records (`done` / `error` /
  `cancelled` / `timeout`) reload verbatim. A record left in the `running` state
  means the process died mid-flight; since the worker thread is gone and cannot
  be resumed, it reloads as **`interrupted`** — never as `done`.
- **Cross-project rule.** A job's file lives only under its own project. Polling
  by `job_id` resolves through the global index; polling *scoped to a specific
  project* only reads that project's directory, so a job that ran under project
  X is **not** visible when resolved scoped to project Y.
- **Bounded reads.** Disk lookups are by `job_id` (one index read + one record
  read) — never a directory scan. Records carry the full result payload; there
  is currently **no automatic cleanup** of `.cortex/cortex_jobs/` (large results
  accumulate there until removed), so treat it like the `.cortex/maps/` cache.

---

## MCP push note

The default delivery mode for both servers is **poll** (the client calls `get_*_status` / `get_*_results` repeatedly). Claude Code does support server-to-client push notifications via `claude/channel` + `--channels`, but these servers do not use that mechanism — poll was chosen for simplicity and portability. If you need push-style delivery you can add it via the FastMCP channel API; it is not impossible, just not wired here.

---

## Default gate profile (size-noise control)

The forensic auditor reads size/complexity thresholds from a **gate profile**. A
default profile ships at the repo root: [`gate_profile.json`](gate_profile.json).
Its only job is to cut **size-noise false-positives** — file-length,
function-length, and nesting-depth warnings firing on legitimately large code —
*without* hiding genuinely extreme outliers (a 2 000-line god-file still
surfaces).

### Where the profile is discovered

`cortex_forensic.self_audit._load_gate_profile_if_present` looks, in order:

1. `<audit-target>/gate_profile.json`
2. `<audit-target>/.cortex/gate_profile.json`
3. **ancestor walk** — the first `gate_profile.json` found in any parent
   directory of the audit target (so a sub-package audit such as
   `run_forensic_audit("cortex_forensic")` still picks up the repo-root default).

A target-local profile always wins over an ancestor one. A missing or malformed
profile is logged and skipped — never fatal. `.cortex/` is git-ignored, so the
**committed** default lives at the repo root.

### How to set your own

Copy the shipped file to your project root and edit `size_thresholds`:

```bash
cp gate_profile.json /path/to/your-project/gate_profile.json
# then edit size_thresholds to taste
```

### Thresholds and their cited sources

JSON forbids comments, so the justification for every value is here. Each value
is a **published linter default**, not an arbitrary constant. `warn` =
MEDIUM-severity heads-up (advisory); `revise` = HIGH-severity "refactor now".

| Key | Value | Source / rationale |
|-----|-------|--------------------|
| `function_warn` | **100** | SonarQube `S138` and PMD `ExcessiveMethodLength` both default to **100** lines. (Clean Code's ~20–60 is an ideal, not a linter default — too aggressive for a real engine, would re-introduce noise.) |
| `function_revise` | **150** | 1.5× the SonarQube/PMD limit — a "clearly excessive" function that should be split. Isolates true outliers (e.g. 325- and 290-line functions in this repo). |
| `nesting_warn` | **5** | pylint `max-nested-blocks` **default = 5**. Nesting depth is the structural-complexity signal the engine actually measures; deep nesting is the same code smell McCabe's cyclomatic-complexity ≈10 guideline targets, expressed as a nesting bound. (SonarQube `S134`=3 is stricter; pylint's 5 is the widely-shipped default and avoids flagging ordinary depth-4 control flow.) |
| `nesting_revise` | **8** | Beyond any common linter's tolerance — genuinely tangled control flow worth flattening. |
| `file_warn` | **750** | SonarQube file-size flag default = **750** lines. |
| `file_revise` | **1000** | pylint `max-module-lines` **default = 1000**. A file past 1 000 lines is a god-file candidate. |

> **Note on cyclomatic complexity.** The size/complexity engine measures file
> LOC, function LOC, and **nesting depth** — it does not compute a McCabe
> cyclomatic-complexity number, and the profile has no `cyclomatic` key (one
> would be dead config). Nesting depth is used as the structural-complexity
> proxy, calibrated to pylint's `max-nested-blocks` default; the McCabe ≈10
> guideline informs that choice rather than being read directly.

### Effect (measured before → after on this repo)

| Audit target | total before | total after | `size.*` before | `size.*` after |
|--------------|-------------:|------------:|----------------:|---------------:|
| `cortex_forensic/`   | 125 | 86 | 92 | 55 |
| `cortex_map_builder/`| 115 | 93 | 49 | 37 |

The remaining `size.*` findings are functions over 100 lines and nesting deeper
than 5 — code that genuinely exceeds the published limits, which is the intended
behavior, not a miss.

---

## Real-world metrics

Measured on **real third-party Python packages** copied out of this repo's
`.venv` (sans `__pycache__`), audited with the shipped default `gate_profile.json`
active (`file_warn 750 / file_revise 1000 / nesting_warn 5`). Reproduce with
[`tests/benchmark_realworld.py`](tests/benchmark_realworld.py)
(`python tests/benchmark_realworld.py` — single-threaded, KB-scale targets, light).

Hardware: Windows 11, CPython 3.11, `workers=1` (forensic enforces this
internally). "mem" = peak RSS delta over the call, sampled at 20 ms in a
background thread. "tokens" = MCP summary-view chars ÷ 4.

| Target | `.py` files | LOC | forensic time | forensic peak RSS | map(`all`) time | map peak RSS |
|--------|------------:|----:|--------------:|------------------:|----------------:|-------------:|
| `filelock` | 14  | 3 385  | 1.6 s  | 8.1 MB | 0.5 s | 4.1 MB |
| `click`    | 17  | 12 179 | 3.7 s  | 2.3 MB | 0.9 s | 2.8 MB |
| `mcp`      | 110 | 20 824 | 10.8 s | 6.2 MB | 1.4 s | 3.5 MB |

Forensic time is roughly linear in file count (~0.1 s/file here); the map build
is much cheaper. Memory stays low (single-digit MB peak delta) — these tools are
light enough to run inline.

### MCP output stays in budget

The summary views (`forensic_server._build_forensic_summary`,
`map_server._build_map_summary`) are what an agent actually receives. Both stay
well under the ~6 k-token budget on every target:

| Target | forensic summary | map summary |
|--------|-----------------:|------------:|
| `filelock` | ~3.0 k tok (11.9 KB) | ~0.5 k tok (1.9 KB) |
| `click`    | ~1.5 k tok (6.1 KB)  | ~0.4 k tok (1.7 KB) |
| `mcp`      | ~1.7 k tok (6.7 KB)  | ~0.6 k tok (2.2 KB) |

(`filelock`'s summary is the largest because its findings are dominated by one
duplication cluster, so the per-`check_id` breakdown is wide. Still < 3 k tokens.)

### Determinism

`run_forensic_audit` is deterministic: run twice on each target, the sorted
`(check_id, file, line)` finding set is identical (no ordering or count drift).

### False-positive reduction on clean code (2026-06)

The default gate selection was re-tuned to cut the ~50 % false-positive rate
observed on clean, idiomatic third-party code. Inspected baseline vs. current
on `filelock` (every finding checked against the cited `file:line`):

| Target | findings before | findings after | actual FPs after |
|--------|----------------:|---------------:|-----------------:|
| `filelock` | 32 | **2** | **0** |
| `click`    | 54 | **33** | low (mostly real `size.*` / `broad_except.swallow`) |
| `mcp`      | 110 | **43** | low (mostly real `size.*` / `broad_except.swallow`) |

The two `filelock` findings that remain are both honest: one `size.file_warn`
(`_soft_rw/_sync.py` is genuinely 858 lines > 750) and one informational
`meta.git_unavailable` (see below). Zero false claims about the code.

Fixes landed (each TDD'd; items 1–5 in
[`tests/test_forensic_fp_clean_code.py`](tests/test_forensic_fp_clean_code.py),
items 6–7 in [`tests/test_dup_and_sqli.py`](tests/test_dup_and_sqli.py)):

1. **`broad_except` cleanup-then-reraise.** `except BaseException: <cleanup>;
   raise` (filelock `_api.py:513`, `asyncio.py:268`) is the correct cancel-
   cleanup idiom — it *re-raises*, it does not swallow. Both the regex
   (`broad_except.base_exception`/`.bare`) and AST
   (`broad_except.hidden_sentinel.bare_or_base`) detectors now skip any handler
   whose body contains a top-level `raise`. Genuine swallows (no re-raise) still
   fire.
2. **`duplication.text_block` inflation + docstrings.** One duplicated region no
   longer emits one finding per sliding-window line (~13 → 1); windows of the
   same file-set at adjacent start lines are merged into a single region. Lines
   inside string literals (shared docstrings / `:param` blocks on sync↔async API
   mirrors) and pure parameter-declaration lines are excluded. Genuine copy-
   pasted **code** blocks are still detected.
3. **Zone-inference gates are now opt-in.** `god_object_zones` infers
   "responsibility zones" from function-name prefixes against a fixed verb list
   (`acquire/release/read/write/open/close/...`); a cohesive read-write-lock
   class collides with that vocabulary and is wrongly flagged — ~0 true
   positives here. It is **off by default** (moved to an opt-in set in
   `self_audit._NOISY_OPT_IN_GATES`) and runs only when explicitly requested
   (`run_forensic_audit(target, gates=["god_object_zones"])` or
   `--gates god_object_zones`). The twin `size_complexity.zone_overload` sub-
   check, which used the *same* name-prefix logic and double-reported the same
   files, was **removed** outright; `size_complexity` keeps its objective
   size/function-length/nesting budget checks.
4. **`api.public_function_signature_change` in no-git mode.** With no git
   baseline (no work tree, or no changed file resolves at `HEAD~1`, e.g. a
   vendored/`site-packages` dir) the old code fell back to a docstring-param-
   count heuristic that fired on every documented variadic API
   (`click.decorators.option(*param_decls, **attrs)` → "0 params vs 3
   documented"). The whole signature-drift check is now **skipped without a git
   baseline** and reported once via `meta.git_unavailable`. It runs normally
   when a real `HEAD~1` diff exists.
5. **Profile fallback foot-gun.** An external target with no ancestor
   `gate_profile.json` previously fell back to the *strict* code-defaults
   (600/800/4) instead of the shipped defaults (750/1000/5). The loader
   (`self_audit._load_gate_profile_if_present`) now falls back to the package's
   **own shipped** `gate_profile.json` (resolved relative to the package, at the
   repo root) as the last resort. A target-local profile still wins.
6. **`duplicate_scan` (near-duplicate code) per-line inflation.** The
   intra-file near-duplicate detector (`assess_near_duplicate_code`) hashes a
   sliding 4-line window, so one duplicated region of N lines emitted N−3
   near-identical findings ("block at lines 118 and 201", "119 and 202", …).
   On `filelock` this produced **39** `duplicate_scan` findings for only a
   handful of real blocks. Adjacent/overlapping window-pairs are now **merged**
   into ONE finding per contiguous block (same region-grouping idea as
   `duplication.text_block`'s `_merge_starts`), reported as a line range:
   `Near-duplicate block at lines 118-126 ↔ 201-209 (9 lines)`. filelock drops
   **39 → 13** — a true merge, not a cap: genuinely separate duplicate blocks
   still each report once (verified: `_api.py` `__call__`/`__init__` signature
   mirror at `118-126 ↔ 201-209` is preserved as a single finding).
7. **Focused SQL-injection detection (cluster 12, `security_scan`).** For
   Python, `assess_security_patterns` flags a dynamic query passed to a
   DB-call site (`.execute`/`.executemany`/`.executescript`/`.query`/`.raw`)
   when the query is built by **f-string** interpolation, **`%`-format**,
   **`str.format()`**, or **`+` string concatenation** with at least one
   non-literal (variable) operand. The flagged string must have real SQL-clause
   structure (`SELECT … FROM`, `UPDATE … SET`, `DELETE FROM`, …) and meet a
   minimum length, so a SQL keyword in prose/log lines does not trip it. A plain
   literal `execute("SELECT 1")`, a parametrised `execute("… ?", (x,))`, and a
   constant concat of two literals (`"SELECT … " + "WHERE …"`) are **not**
   flagged.
   **Limits (honest):** detection is purely local/syntactic — it fires only
   when the dynamic string is the *direct first argument* of the DB call.
   There is **no taint tracking**: a query assembled in a prior statement
   (`q = "SELECT … " + user_input; db.execute(q)`), passed through a helper, or
   stored on a variable first is **not** detected. Non-Python languages get the
   regex security patterns only (no SQLi AST rule). This is deliberately
   low-false-positive, not full SQLi coverage.
8. **`debug_print_scan` substring / CLI-output false positives.** The detector
   matched the substring `print(` anywhere on a line, so it fired on (a) `print(`
   *inside a string literal* (e.g. a detector's own pattern tuple
   `(..., "print(", ...)`), (b) lines already carrying `# noqa: debug_print_scan`,
   and (c) intentional user-facing `print()` in CLI/output functions (the path
   allowlist only knew the pre-migration `BRAIN/autoforensics/self_audit.py` path,
   not the packaged `self_audit.py`). For **Python** the gate is now AST-driven:
   only a line carrying a genuine `print(...)` **call** (`ast.Call` with
   `func=Name('print')`) can be flagged — a `print(` in a string literal or an
   attribute call (`obj.print(...)`) is never flagged. On a file that fails to
   parse it falls back to requiring the stripped line to **start** with `print(`
   (statement position). Across all languages the gate now (i) respects
   `# noqa: debug_print_scan` and a bare `# noqa` on the offending line, and
   (ii) skips prints inside conventionally-named output functions — name starts
   with `print_`/`_print_`, or is `main`/`cli`/`run`/`cli_main` (and underscore
   variants). The rule is deliberately conservative: a `print_*` function
   elsewhere in the file does **not** silence a stray `print()` in an unrelated
   normal function, and a genuine `print("DEBUG", x)` in ordinary code is still
   flagged. On `cortex_forensic` itself this cut `debug_print_scan` **12 → 0**
   (all 12 were FPs: 10 in `print_human_summary()`, 2 in detector pattern
   tuples); the corpus oracle (`tests/oracle/sample_quality.py:63`) stays flagged.
   TDD'd in [`tests/test_debug_print_fp.py`](tests/test_debug_print_fp.py).

**Residual honesty.** The remaining output is dominated by the objective
`size.*` gates (real breaches of published linter limits) and
`broad_except.swallow` (genuine `except: pass`). These are trustworthy. The
zone heuristic still exists as an *opt-in* capability for teams that want it on
their own diffs — re-enable it per run via the `gates` argument. It is not
deleted, just no longer in the default scan.

---

## Per-project configurability

Three knobs let a project tune the forensic auditor without forking it:
**disable noisy gates**, **raise the severity floor**, and **add your own gate**.

### Disable specific gates — `.cortex/disabled_gates.json`

Drop a `disabled_gates.json` into your project's `.cortex/` directory to switch
off gates that are noisy for your codebase. `run_forensic_audit` auto-loads it
from `<project_dir>/.cortex/disabled_gates.json`. Two accepted shapes:

```jsonc
// a bare list of gate check_ids …
["broad_except", "duplication"]
```
```jsonc
// … or an object with a "disabled" key
{ "disabled": ["broad_except", "duplication"] }
```

A disabled gate never runs (produces no findings) and is reported in
`meta["gates_skipped"]` with reason `"disabled_by_project"`:

```python
from cortex_forensic import run_forensic_audit

res = run_forensic_audit("/path/to/project")
# .cortex/disabled_gates.json contains ["broad_except"]
assert {e["gate_id"] for e in res["meta"]["gates_skipped"]
        if e["reason"] == "disabled_by_project"} == {"broad_except"}
```

Behavior:

- The disable list takes precedence over every other resolution rule — a
  disabled gate is always reported as `disabled_by_project`, even one that the
  static-mode policy or a `gates=` filter would have skipped anyway.
- **Missing or empty file → no-op.** Nothing is disabled; all gates run.
- **Malformed file never raises.** A JSON-syntax error, an unreadable file, or a
  wrong-typed payload is *logged-and-ignored* (narrow exception handling, no
  bare `except`): the audit completes, nothing is disabled, and a
  `meta.profile_load_failed` finding (HIGH/WARN) records the failure so the
  silent-disable is fail-loud rather than swallowed.
- `.cortex/` is git-ignored by default in this repo's audit policy, so the file
  is a *local* opt-out unless you commit it deliberately.

The same file is honored by the CLI (`python -m cortex_forensic.self_audit
--project <dir>`).

> Gate ids are the `check_id` values — run `python -m cortex_forensic.self_audit
> --list-gates` to print the file-based gates, or read the `GATE_SPECS` table in
> [`cortex_forensic/gate_packs/universal.py`](cortex_forensic/gate_packs/universal.py).
> Note a *family* gate id (`broad_except`) and its sub-checks emitted under a
> dotted child id (`broad_except.return_none`) are produced by the same runner;
> disabling the family id (`broad_except`) stops that runner entirely. A
> *separately registered* gate such as `broad_except.hidden_sentinel` has its
> own id and must be disabled separately.

### Raise the severity floor — `severity=`

`run_forensic_audit(project_dir, *, severity="LOW")` filters the returned
`findings` to those **at or above** the floor. Ordering is
`LOW < MEDIUM < HIGH < CRITICAL` (case-insensitive); the default `"LOW"` returns
everything.

```python
res = run_forensic_audit("/path/to/project", severity="HIGH")
# res["findings"] contains only HIGH and CRITICAL findings.
```

The `meta.*` counters (`severity_counts`, `total_findings`, `category_counts`)
are computed **before** the floor is applied, so they always reflect the full
finding set; `meta["findings_after_severity_filter"]` records the post-filter
count whenever a non-LOW floor is used. The process exit code is likewise driven
by the unfiltered HIGH/CRITICAL counts.

### Add your own gate

There is **no plugin auto-discovery** — the gate set is the module-level
`GATE_SPECS` tuple in
[`cortex_forensic/gate_packs/universal.py`](cortex_forensic/gate_packs/universal.py),
resolved once at import into `DEFAULT_GATE_CHECKS`
([`gate_registry.py`](cortex_forensic/gate_registry.py)). Registering a gate
means adding a spec to that tuple. The spec shape is a 3-tuple:

```python
(check_id, category, runner)
#   │          │         └── Callable[[PostExecGateContext], GateCheckResult]
#   │          └── a cortex_forensic._shared.GateCategory enum member
#   └── str, the gate id (also the prefix for any dotted child ids it emits)
```

The **runner** takes the synthetic `PostExecGateContext` (its
`ctx.file_snapshots` maps each touched file's normalized path → a
`GateFileSnapshot` with `.text`, `.line_count`, `.exists`) and returns a
`GateCheckResult`:

```python
from cortex_forensic._shared import (
    GateCheckResult, GateFinding, GateCategory, GateSeverity,
    GateImpact, EvidenceReference,
)

def run_no_print_checks(ctx) -> GateCheckResult:
    findings = []
    for path, snap in ctx.file_snapshots.items():
        if not snap.exists or not path.endswith(".py"):
            continue
        for lineno, line in enumerate(snap.text.splitlines(), start=1):
            if line.lstrip().startswith("print("):
                findings.append(GateFinding(
                    check_id="no_print",
                    category=GateCategory.REPORTING,
                    title="Stray print() in source",
                    severity=GateSeverity.LOW,
                    impact=GateImpact.WARN,
                    summary=f"print() at {path}:{lineno}",
                    recommendation="Use logging instead of print().",
                    evidence=(EvidenceReference(
                        kind="line", path=path, detail=f"L{lineno}", ok=False),),
                    fingerprint=f"no_print:{path}:{lineno}",
                ))
    return GateCheckResult(
        check_id="no_print", category=GateCategory.REPORTING,
        findings=tuple(findings),
    )
```

To wire it in (the supported path — edit the pack):

1. Add `("no_print", GateCategory.REPORTING, run_no_print_checks)` to
   `GATE_SPECS` in `gate_packs/universal.py`.
2. Add `"no_print"` to the `_FILE_BASED_GATES` allowlist in
   [`cortex_forensic/self_audit.py`](cortex_forensic/self_audit.py) — the static
   auditor only runs gate ids in that set (anything else is reported as
   `not_file_based` and skipped). A runtime-only gate would instead get a
   `skip_in_static` flag in `GATE_FLAGS`.

Each `GateFinding` is validated on construction: `confidence` must be in
`[0.0, 1.0]`, and a non-`"applicable"` `applicability` requires a non-empty
`applicability_reason` (see `GateFinding.__post_init__` in `_shared.py`).

> If you must register a gate **without** editing the pack (e.g. a downstream
> wrapper), `cortex_forensic.gate_registry.DEFAULT_GATE_CHECKS` is a plain tuple
> you can extend before calling `run_gates`, and `run_gates(..., gates_filter=…)`
> selects a subset — but a new id still has to be present in `_FILE_BASED_GATES`
> to run in static mode, so editing the pack is the honest, complete path.

### `forensic_clusters` in static mode (static-safe subset)

The `forensic_clusters` pack bundles ~40 cluster runners. Most are purely
static (they read only `file_snapshots` / text / AST): security patterns,
secrets, mutable defaults, resource leaks, hardcoded paths, dead code,
unreachable code, shadowed builtins, magic numbers, TODO debt, import cycles,
exception swallowing, and more. A minority are **runtime-only** — they need a
real post-execution context (`artifact_refs`, `transport_mode`,
reported-vs-observed changed files, validation-contract proofs, or a disk
re-read compared against an expected hash) and are meaningless / false-positive
prone without it. The runtime-only set is listed in
[`forensic_cluster_runners/core.py`](cortex_forensic/gate_checks/forensic_cluster_runners/core.py)
as `_RUNTIME_ONLY_CLUSTERS` (`cluster2_success_without_proof`,
`cluster3_proxy_as_truth`, `cluster4_config_accepted_ignored_*`,
`cluster6_state_divergence`, `cluster7_fallback_hides_truth`,
`cluster10_edit_consistency`, `cluster11_mutation_verified`).

So the pack is **not** flagged `skip_in_static`. Instead, when `run_gates`
hands it a synthetic static context (`_is_static_mode(ctx)` → no runtime
signals), the runner filters the runtime-only clusters out and runs only the
static-safe checks. When a real execution context is present the full pack runs
unchanged. The worst FP this prevents is `cluster11_mutation_verified`: it
hashes the *decoded* snapshot text but the assessor hashes the *raw* disk bytes,
so every CRLF / BOM file would otherwise fire a bogus "content DIVERGED" HIGH.

> **`dead_code_scan` caveat.** Cluster 20 marks a public function "dead" when it
> is not referenced anywhere in the **scanned set**. `run_forensic_audit` always
> discovers the whole project directory, so cross-file references resolve and it
> is accurate (0 findings on `filelock`, which uses `__all__`). It can over-report
> only on a *partial / single-file* scan, where a function's caller lives in a
> file outside the scan — that path is not used by `run_forensic_audit`. Findings
> are MEDIUM, and names in `__all__`, framework-decorated, or matching standalone
> markers are already classified as `standalone_utility` and skipped.

---

## Running tests

```bash
pytest tests/ -p no:cacheprovider
```

No parallel execution (`-n auto`) — keep it light, tree-sitter grammars load on first call.
