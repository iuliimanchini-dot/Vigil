# code-map — User Guide

A structural mapper for codebases, exposed as an MCP server. You point it at a project, it reads the code with `tree-sitter` / AST, and builds maps of how the code is organized. Like its companion auditor, it **never runs your code**.

## What it is

`code-map` is a read-only static mapper. It parses your source into syntax trees and produces structured maps: what imports what, which symbols are defined, where the runtime entry points are, what data contracts exist and how they drift, who writes to files / DB / env, where the risk hotspots are, and where a refactor's natural boundaries lie. It is for *understanding* a codebase, not for finding bugs (use the `forensic-audit` server for that).

Supported languages: **Python, Go, Java, JavaScript, TypeScript, Swift**.

## What it gives you

It produces **8 map types**, of which **6 work out of the box** with zero configuration:

- **structural** — imports and symbols. Accurate.
- **data_contract** — dataclasses / structs, their shape, drift detection, and writers / readers.
- **hotspot** — a risk score per file.
- **conflict** — schema conflicts.
- **authority** — who writes files / DB / env. Auto-surfaces writes with no config needed.
- **runtime** — entry points (`__main__` / async). Auto-surfaces with no config needed.

The 7th map, **refactor_boundary**, is **seed-driven**: it needs a refactor goal to work. (An eighth, `findings`, is derived from the others.)

Output is **summary-first**: by default you get per-map-type counts plus the top entries of each map. Ask for one full map with `map='structural'`, or `view='full'` for all maps.

The output is **deterministic** — the semantic diff ignores timestamps, so the same code yields the same maps. Results are **cached on disk** under `<project>/.cortex/`, which makes re-runs cheap.

## When to use

- When you arrive at an unfamiliar codebase and need to understand its architecture quickly.
- To find what imports or depends on what.
- To locate runtime entry points or risk hotspots.
- To scope a refactor (and, with a seed, to find its boundaries).
- To see who writes to files / databases / environment — the authority map surfaces write sites automatically.

It is **not** a code-quality auditor — for bugs, swallowed exceptions, and security smells, use the `forensic-audit` server.

## How to install and use

Currently this is a **local editable install** (it is not on PyPI yet). It works on the machine where you install it; publishing to PyPI for use on other machines is pending.

From the `vigil` repository root:

```bash
pip install -e .   # from the vigil repo
claude mcp add code-map -s user -- <abs-path-to-venv-python> -m vigil_mcp.map_server
```

Replace `<abs-path-to-venv-python>` with the absolute path to the Python interpreter in your virtual environment, e.g. on Windows:

```
C:\Users\You\path\to\vigil\.venv\Scripts\python.exe
```

Once added, the server exposes a **background job + poll** API. The typical flow is:

1. `start_code_map(path)` → returns a `job_id` and the `resolved_path`. Leave `path` empty to auto-detect the project root by walking up from the current directory.
2. `get_code_map_status(job_id)` → poll until `status == "done"`.
3. `get_code_map_results(job_id)` → the compact summary (per-map counts + top entries). Read this first.
4. Drill in: `get_code_map_results(job_id, map='structural')` for one full map, or `view='full'` for all maps (both paginated via `page=`).

To re-read maps built in an earlier session without starting a new job, use `load_code_map_by_path(path)`.

The project root is auto-detected when you omit `path`.

## Pros

- **6 of 7 maps work with zero configuration.**
- **Rich `data_contract` map** with drift detection.
- **Accurate structural map.**
- **6 languages** (Python, Go, Java, JS, TS, Swift).
- **Deterministic** — the semantic diff ignores timestamps.
- **Summary fits your context budget.**

## Cons and limits

Being honest about the gaps:

- **`refactor_boundary` needs a seed** (a refactor goal). Without one it does not produce boundaries.
- **The `authority` map's Python discovery is incomplete.** It catches `open('w')`, `write_text`, and `json.dump`, but **not** the `os.fdopen` + `os.replace` atomic-write idiom, and not DB / env writes. (The Go / Java adapters do catch DB writes.)
- **Some entry points are not surfaced.** Entry points exposed only through packaging `console_scripts` (with no in-file `__main__`) are not detected.
- **A single map's full view can be large** — up to ~32k chars on a mid-size project. It is paginated, so page through it rather than expecting it all at once.

## Tuning

- Most maps need **no configuration** — 6 of the 7 work out of the box.
- The one exception is **`refactor_boundary`**: provide a refactor goal as its seed so it knows what boundary to compute.
- Use the **summary first**, then drill into a single map with `map='<type>'` (e.g. `map='structural'`), or get everything with `view='full'`. Both views are paginated via `page=`.
- Results are **cached on disk** under `<project>/.cortex/`; `load_code_map_by_path(path)` re-reads them without a new build.

## Seeds (optional)

A **seed** is a small JSON file you drop into `<project>/.cortex/map_seeds/` to *refine* a map's output. **You almost never need one** — 6 of the 8 maps work out of the box with no seed. Seeds matter for three maps:

- **authority** → `authority_domains.json`. Without a seed, every write site is auto-surfaced as its own inferred per-writer domain (already useful). With a seed, writers are **grouped into named domains** by glob patterns — e.g. all config writers under one `config_writers` domain.
- **runtime** → `runtime_seed.json`. Auto-discovery finds in-file entry points (`__main__` / async). A seed lets you **declare extra runtime nodes** that static analysis cannot see — cron jobs, externally-launched workers, `console_scripts` entry points.
- **refactor_boundary** → `refactor_boundaries.json`. This map is essentially **seed-driven**: the seed defines the refactor *goal* and which files are allowed / watched / forbidden. Without a seed it produces no boundaries.

When you'd want one: to group authority writes into domains; to declare runtime nodes the scanner can't reach; or to set a refactor goal/boundary.

### Format

Each seed is a JSON object with a `schema_version` and a list of entries. Ready-to-copy templates live in `docs/examples/map_seeds/`.

**`authority_domains.json`** — required: `schema_version`, `domains[]`; each domain needs `authority_domain` (the domain name) and `target_file_patterns` (globs; a writer joins the domain when one of its resolved write targets matches):

```json
{
  "schema_version": "1.0",
  "domains": [
    {
      "authority_domain": "config_writers",
      "target_file_patterns": ["config/*.json", "**/settings.py"]
    }
  ]
}
```

**`runtime_seed.json`** — required: `schema_version` (must be exactly `"1.0.0"`), `nodes[]`; each node needs `node` (its name). Optional per node: `defined_in`, `kind`, `side_effects`, `depends_on_env`, `tags`, and a few more:

```json
{
  "schema_version": "1.0.0",
  "nodes": [
    {
      "node": "cron_nightly_report",
      "defined_in": "ops/cron.py",
      "kind": "scheduled_job"
    }
  ]
}
```

(`refactor_boundaries.json` follows the same `schema_version` + `entries[]` shape, where each entry requires a `boundary_id` plus `goal` / `allowed_files` / `forbidden_files`.)

### Where to put it

Place the file at `<project>/.cortex/map_seeds/<name>.json` in the project you are mapping. The directory is read on every build; a missing seed is not an error (the map falls back to auto-discovery). Copy a template from `docs/examples/map_seeds/` and edit it.
