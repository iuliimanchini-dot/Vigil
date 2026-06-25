# Real-world metrics — raw notes

Backing data for the "Real-world metrics" section of the top-level `README.md`.
Regenerate with:

```
.venv/Scripts/python.exe tests/benchmark_realworld.py
```

That writes machine-readable results to `tests/_benchmark_results.json` and
prints the summary table. All numbers below use the **shipped default
`gate_profile.json`** (`file_warn 750 / file_revise 1000 / function_warn 100 /
function_revise 150 / nesting_warn 5 / nesting_revise 8`), copied into each
throw-away target copy so the audit resolves the default profile rather than the
stricter hardcoded code fallback (600/800/4).

Targets are real packages from this repo's `.venv/Lib/site-packages`, copied
without `__pycache__`. Single-threaded (`workers=1`). Windows 11, CPython 3.11.

## Headline table

| Target | files | LOC | forensic s | forensic RSS Δ | map s | map RSS Δ | forensic findings | exit |
|--------|------:|----:|-----------:|---------------:|------:|----------:|------------------:|-----:|
| filelock | 14  | 3 385  | 1.62  | 8.1 MB | 0.47 | 4.1 MB | 32  | 0 |
| click    | 17  | 12 179 | 3.68  | 2.3 MB | 0.92 | 2.8 MB | 54  | 1 |
| mcp      | 110 | 20 824 | 10.83 | 6.2 MB | 1.41 | 3.5 MB | 110 | 1 |

(RSS Δ = peak resident-set delta over the call, psutil sampled at 20 ms in a
background thread. The absolute value is small and somewhat noisy run-to-run;
the takeaway is single-digit MB, not a precise figure.)

## MCP summary output size (agent-visible payload)

| Target | forensic summary chars | forensic ≈tok | map summary chars | map ≈tok |
|--------|-----------------------:|--------------:|------------------:|---------:|
| filelock | 11 910 | 2 977 | 1 874 | 468 |
| click    | 6 141  | 1 535 | 1 722 | 430 |
| mcp      | 6 653  | 1 663 | 2 211 | 553 |

All well under the ~6 k-token budget (`OUTPUT_CHAR_LIMIT = 80 000` chars caps the
worst case regardless).

## Determinism

Forensic audit run twice per target; sorted `(check_id, file, line)` sets compared.

| Target | run 1 findings | run 2 findings | identical set |
|--------|---------------:|---------------:|:-------------:|
| filelock | 32  | 32  | yes |
| click    | 54  | 54  | yes |
| mcp      | 110 | 110 | yes |

## Per-`check_id` breakdown

### filelock (32) — FP inspection target

| check_id | n | verdict |
|----------|--:|---------|
| duplication.text_block | 15 | noise (shared docstrings / sync↔async param lists; per-line over-count) |
| god_object_zones.zone_inflation | 7 | FALSE (zone = function-name prefix; lock domain verbs) |
| size_complexity.zone_overload | 5 | FALSE (same mechanism, lower threshold, double-counts) |
| broad_except.base_exception | 2 | FALSE (`except BaseException: …; raise` — re-raises, correct cancel cleanup) |
| broad_except.hidden_sentinel.bare_or_base | 2 | FALSE (same two re-raising sites) |
| size.file_warn | 1 | TRUE actionable (`_soft_rw/_sync.py` 858 > 750) |

- Strict FP rate: 16/32 ≈ 50 %.
- Genuinely actionable: 1/32 ≈ 3 % (treating the docstring-dup cluster as
  non-actionable noise).
- Noisiest gate: the **zone family** (`god_object_zones` +
  `size_complexity.zone_overload` = 12/32).

### click (54)

| check_id | n |
|----------|--:|
| broad_except.swallow | 8 |
| api.public_function_signature_change | 7 |
| duplication.text_block_intra | 6 |
| size.nesting_warn | 5 |
| context_fallback_save.fallback_without_else | 4 |
| size.function_warn | 4 |
| god_object_zones.zone_inflation | 3 |
| size.file_warn | 3 |
| duplication.text_block | 2 |
| atomic_write_safety.missing_tmpfile_rename | 2 |
| size.file_too_large | 2 |
| size.function_too_large | 2 |
| size_complexity.zone_overload | 2 |
| broad_except.base_exception | 1 |
| broad_except.hidden_sentinel.bare_or_base | 1 |
| encoding.subprocess_missing_encoding | 1 |
| size.nesting_too_high | 1 |

Spot-checked `api.public_function_signature_change` — all 7 are degraded-mode
(no git "before") docstring-param-vs-signature mismatches on **variadic** public
APIs, e.g. `click.decorators.option(*param_decls, cls=None, **attrs)` reported as
"0 params vs 3 documented." False positives.

### mcp (110)

| check_id | n |
|----------|--:|
| duplication.text_block_intra | 48 |
| size.function_warn | 12 |
| api.public_function_signature_change | 10 |
| god_object_zones.zone_inflation | 7 |
| size.nesting_warn | 5 |
| broad_except.swallow | 4 |
| context_fallback_save.fallback_without_else | 4 |
| broad_except.return_none | 3 |
| size_complexity.zone_overload | 3 |
| size.function_too_large | 3 |
| size.file_too_large | 3 |
| duplication.text_block | 2 |
| atomic_write_safety.missing_tmpfile_rename | 2 |
| broad_except.hidden_sentinel.silent_return | 1 |
| toctou_check_then_act.race_window | 1 |
| size.file_warn | 1 |
| size.nesting_too_high | 1 |

`duplication.text_block_intra` dominates (48) — intra-file repeated blocks, the
same per-line/per-block over-counting pattern seen on filelock.

## Bottom line

Fast, light, deterministic. The **size/threshold** gates report honest factual
breaches. The **structural-inference** gates — the zone family and
`api.public_function_signature_change` in degraded (no-git) mode — are the noise
source and drive ~50 % strict FP on clean library code. For third-party/vendored
code, disable them via `.cortex/disabled_gates.json`:
`["god_object_zones", "size_complexity", "api"]`.
