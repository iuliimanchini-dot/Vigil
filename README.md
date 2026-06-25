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

## Running tests

```bash
pytest tests/ -p no:cacheprovider
```

No parallel execution (`-n auto`) — keep it light, tree-sitter grammars load on first call.
