# Autonomous Fix Plan — vigil (state survives compaction)

**Directive (Julio, autonomous mode):** fix CODE (not docs) so that: (1) 5 languages
really work, (2) FP really drops, (3) add ML/NN checks, (4) scaling bug fixed, (5) etc.
Verify everything myself (no trusting agent summaries). Checkpoint-commit per phase.
Firm line: push/PyPI only on explicit Julio command (commits OK as checkpoints).

## BASELINE (Verified 2026-06-28, before any fix)
- Self-audit `vigil_forensic`: **187 findings / 22.1s** (60 files).
- Top noise: size 57, unused_import_scan 30, duplicate_scan 30, exception_swallow 10,
  broad_except 9, log_level 7, hardcoded_path 7, boundary_validation 6.
- Severity: 80 med / 31 high / 76 low.
- Scaling bug VERIFIED in code: legacy_debt.py:319 (unused_shim) + :460 (shape_adapter)
  iterate `all_project_files_content` per-module (O(modules × all_files)); duplication
  rglob project_dir. Hangs on big monorepo subtree (12+min on rubik v21/trading 38 files).
- Counts: 60 GATE_SPECS, 104 cluster check_ids, 260 total check_id literals.

## PHASES (order = priority)
- [ ] **P0 Scaling fix** — build caller-index ONCE (stem→importers), scoped to scanned
  subtree; legacy_debt + duplication read index. VERIFY: v21/trading <30s, findings identical, oracle 22/22.
- [ ] **P1 ML/NN gates** — NEW gate pack: look-ahead bias (rank/rolling before shift),
  train/test leakage (fit on test/full), NaN-in-output, scaler fit on test, target leakage,
  non-deterministic seed. Python AST. VERIFY: oracle corpus for ML (write positive+negative cases).
- [ ] **P2 5 languages real** — JS contracts (tree-sitter), TS contracts/runtime via
  tree-sitter (not regex). VERIFY: per-lang adapter tests, supports_* flags honest.
- [ ] **P3 FP down** — measure top categories (size/unused_import/duplicate), kill real FPs,
  keep oracle 22/22. VERIFY: self-audit 187→lower, per-category before/after.
- [ ] **P4 shim-FP** — __init__.py reexport → skip in unused_shim. VERIFY: vigil __init__ not flagged.
- [ ] **P5 README honest + republish prep** — 60 gates/260 checks, lang parity honest;
  version bump; full suite+oracle clean. VERIFY: forensics→fix→validate→forensics clean.

## PROGRESS LOG
- 2026-06-28: baseline captured. Starting P0.
