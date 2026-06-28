# Security & Privacy

## What vigil can access

vigil performs **static analysis only** — it reads your source files with tree-sitter /
Python `ast` and **never executes your code, tests, or build**. It makes **no network
calls** and does not phone home.

## What vigil writes (local only)

Results are cached locally, scoped to the analyzed project:

- `<project>/.cortex/maps/` — structural maps (JSON)
- `<project>/.cortex/cortex_jobs/<id>.json` — background-job results (survive a server restart)
- `~/.cortex/cortex_jobs_index/` — a per-user index mapping job ids → project paths

Nothing leaves your machine. Add `.cortex/` to your `.gitignore` (vigil's own repo already does).

## MCP trust model

The MCP servers (`code-map`, `forensic-audit`) run as **local stdio subprocesses** started
by your MCP client (e.g. Claude Code). They inherit the filesystem access of the launching
process; they open no sockets and send nothing over the network. The audit reads code — it
never runs it.

## Resource safety

Designed not to hang the host:

- max 2 concurrent jobs, single-worker forensic execution
- output paginated and capped (~80 000 chars/page)
- anti-hang **file-count guard** (`max_files`, default 800) — oversized repos are skipped
  with a suggestion to scan a sub-tree instead of locking up

## Reporting a vulnerability

Open a private GitHub security advisory on
[iuliimanchini-dot/Vigil](https://github.com/iuliimanchini-dot/Vigil/security/advisories),
or a regular issue for low-severity findings. **Do not include secrets** in reports.
