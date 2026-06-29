# Changelog

All notable changes to `vigil-codeintel` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [0.1.3] — 2026-06-29

### Added
- **Authority target resolution across all languages** — write-site maps now resolve the
  actual target path/resource, not just the receiver variable. Go, Java, TypeScript,
  JavaScript, and Swift adapters trace string-literal / variable-assignment / path-builder
  targets (`filepath.Join`, `Paths.get`/`Path.of`, `path.join`, `URL(fileURLWithPath:)`,
  `appendingPathComponent`) into `resolved_target` + `provenance` (`string_literal` /
  `path_constructor` / `function_parameter`); unresolvable targets stay
  `__unknown_target__` (never a guessed path). The authority map surfaces resolved
  targets + provenance for every language (previously Python-only). Oracle corpora under
  `tests/oracle_target_*/`.

### Changed
- `authority_builder` now prefers an adapter's `resolved_target`/`provenance` when the
  adapter resolved it, falling back to the thin `target_hint`/unknown otherwise.

## [0.1.2] — 2026-06-29

### Added
- **Swift support (6th language)** — `SwiftAdapter` (tree-sitter-swift): structural,
  data-contract (struct/class/protocol/enum/actor), runtime (`@main`, `Task`/`DispatchQueue`),
  and authority (`write(to:)`, `FileManager`, `.save()`) maps. Forensic `SWIFT_PROFILE`
  plus two AST-precise safety gates: `swift.force_unwrap` and
  `swift.implicitly_unwrapped_optional`.
- Oracle corpora `tests/oracle_unify/` and `tests/oracle_swift/` that exercise the
  authority resolver / runtime merge and Swift extraction the main tree can't.

### Changed
- **Python now routes through the source adapter for ALL four maps** — true 6-language
  parity. `authority` and `runtime` joined `structural` and `data_contract`: the write-site
  resolver moved to `_authority_ast.py` and the runtime visitor is consumed via the adapter.
  Verified byte-identical to the previous builder output on three targets (vigil_mapper,
  vigil_forensic, oracle); Go/Java/TS/JS maps unchanged.
- Docs reflect six supported languages (capability matrix, usage docs EN/RU/ZH).

## [0.1.1] — 2026-06-29

### Added
- **`agent-brief`** — `get_code_map_results(view="brief")` synthesises an agent-facing
  preflight briefing from the maps: entry points, state write-sites (check before
  editing), riskiest files, conflicts, and a suggested read order. Hand it to an agent
  before it edits an unfamiliar repo instead of letting it read everything.

### Fixed
- **ML gates were not running** in `run_forensic_audit` — the `ml.*` pack was defined but
  never wired into the file-based gate set. Now fires (look-ahead, train/test leakage,
  missing seed, non-deterministic split).
- **`exception_swallow`** no longer flags idiomatic control-flow catches
  (`except KeyboardInterrupt | BrokenPipeError | GeneratorExit | SystemExit: pass`).
- Removed 75 unused imports (dead code) flagged by the tool on itself.

### Changed
- **Honest check count** — README and marketplace now state **190+ checks across ~110
  families** (previously inconsistent "40+" vs "22").
- **Python source adapter** now extracts contracts/runtime/writers via `ast` (parity with
  the Go/Java/TS tree-sitter adapters; previously L1 stubs returning `[]`).
- Forensic caller-search gates rebuilt around a single caller-index (O(N²)→O(N)) — large
  monorepos no longer hang.
- Docs: result-first README ("pre-action intelligence layer for coding agents"),
  added `SECURITY.md` (static-only / no-network / `.cortex` privacy) and this changelog.

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
