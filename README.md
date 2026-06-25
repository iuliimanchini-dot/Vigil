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

## Running tests

```bash
pytest tests/ -p no:cacheprovider
```

No parallel execution (`-n auto`) — keep it light, tree-sitter grammars load on first call.
