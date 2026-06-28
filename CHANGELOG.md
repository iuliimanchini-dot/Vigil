# Changelog

All notable changes to `vigil-codeintel` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-28

First public release.

### Added
- **`vigil_mapper`** — structural code maps (imports/dependencies, symbols, runtime
  entry points, write-authority, data contracts, risk hotspots, refactor boundaries).
  Python via stdlib `ast`; Go/Java/JS/TS via tree-sitter. The Python source adapter
  extracts contracts/runtime/writers directly via `ast` (parity with the tree-sitter
  languages).
- **`vigil_forensic`** — 190+ distinct static checks across ~110 families: swallowed
  exceptions, security injection, oversized/over-nested code, cross-file duplication,
  contract drift, and an **ML/NN correctness pack** (`ml.*`): look-ahead bias
  (`.shift(-N)`), train/test leakage (scaler `fit` on `*_test`/`*_val`), missing RNG
  seed, non-deterministic split.
- **`vigil_mcp`** — two FastMCP stdio servers (`code-map`, `forensic-audit`) with a
  background-job + polling API, summary-first output (~3k tokens by default), and job
  persistence across server restart.
- **Resource safety** — max 2 concurrent jobs, single-worker forensic, output cap,
  anti-hang `max_files` guard (default 800).
- **Distribution** — Claude Code plugin packaging (`.claude-plugin/`, root `.mcp.json`)
  and PyPI trusted-publishing via GitHub Actions OIDC (no API tokens).

### Performance
- Forensic caller-search gates rebuilt around a single caller-index pass
  (O(N²)→O(N)); large monorepos no longer hang.

### Known limitations
- Static analysis only — never executes target code.
- Security checks (e.g. SQLi) are syntactic; no taint tracking.
- See README "Known limitations" for the full list.
