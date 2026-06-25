# Roadmap: cortex-codeintel → полноценный полезный MCP-сервер

## Где мы сейчас (честно)
Репозиторий `cortex-codeintel` (6 коммитов): 3 пакета — `cortex_map_builder`, `cortex_forensic`, `cortex_mcp` (2 FastMCP stdio-сервера: `code-map`, `forensic-audit`).

**Сделано и проверено:**
- Extraction из Vigil (D), MCP-серверы фоновые (E), packaging+CI yaml (F).
- FP-шум: forensic на себе 375 → **125** (BOM/dup/broad_except, G-A).
- Ресурсы: `max_file_mb` guard, LRU source-cache, `del` карт, job-timeout, реальный cancel (G-B).
- Конкурентность: `FileLock` + atomic `os.replace` — безопасно.
- Безопасность: дефолт статический (tree-sitter/ast); runtime-trace opt-in.

**Сделано в сессии 2 (2026-06-26) — verified мной:**
- ✅ **G1** Vigil-артефакты ВЫЧИЩЕНЫ полностью: runtime_tracer path→cortex; 4 INTERFACE-гейта (phantom/declared/rendered/dead_surface) + dead assess_* helpers удалены; producer-метки→cortex. **taint=0 во всех 3 пакетах** (commits 7b7ae9e, 13dcdc7, 2e3daf6).
- ✅ **G3** Output summary-first (default view='summary', реальный forensic ~3k токенов vs 80k) + auto-path (`_resolve_project_root`, path опционален) (d0d568b).
- ✅ **G2.1 детерминизм**: forensic SET+ORDER stable (5 прогонов идентичны); map детерминирован через `semantic_map_diff` (freshness/built_at в `_IGNORED_FIELDS`). Для CI — semantic_map_diff, не raw hash.
- ✅ **G2.2 инкрементальность**: on-disk cache пишется (.map_cache, 61 файл/60 src). Cross-process speedup ~1x на МАЛЫХ проектах (8-map build overhead > parse). Документировано как есть.
- ✅ **G2.3** job-персистентность: disk-backed `.cortex/cortex_jobs/<id>.json` (atomic), результаты переживают рестарт, running→interrupted (8db23b7).
- ✅ **G2.4** конфигурируемость: `.cortex/disabled_gates.json` + severity floor + custom-gate doc (4407bfa).
- ✅ **G4** дефолтный `gate_profile.json` (SonarQube/pylint/PMD пороги): self-audit 125→**84**; size 92→55 (9cd94a3).

**Осталось (требует Julio / реальной среды):**
- **G5** реальная `claude mcp add` + прогон на 2-3 проектах (метрики время/память/токены) — требует подключения в Claude Code (среда Julio).
- **G4.2** глубокий FP-rate% на стороннем проекте (mcp site-packages дал counts, не ручную FP-оценку).
- **G6.2** реальный прогон CI (yaml есть, не запускался на OS×Python).
- **G7** публикация — outbound, ТОЛЬКО по команде Julio.
- (опц.) cross-process cache speedup, FOC job cleanup GC, channels-push.

## Acceptance: что значит «полноценный полезный»
- [ ] Нет Vigil-артефактов и ложных findings от project-specific гейтов.
- [ ] Вывод summary-first — не выбивает контекст (< ~6k токенов по умолчанию).
- [ ] Auto-таргетинг проекта + явный выбор папки.
- [ ] Конфигурируемость: отключить гейты, severity-порог, добавить свои.
- [ ] Детерминированный вывод (для CI diff) + инкрементальность (re-run дешевле).
- [ ] Job-персистентность (переживают рестарт сервера) ИЛИ явно задокументировано.
- [ ] Безопасность задокументирована (static-default; runtime-trace opt-in).
- [ ] FP ≈ 10% на реальных проектах (через профиль).
- [ ] Реально подключён в Claude Code + проверен на 2-3 проектах (метрики: время/память/токены/польза).
- [ ] CI зелёный на всех OS×Python; README честный.

---

## План

### G1 — Зачистка extraction-артефактов  [CRITICAL: корректность]
- **G1.1** `runtime_tracer.py:84` + `runtime_tracer_entry.py`: argv `BRAIN.autoforensics...` → `cortex_map_builder.runtime_tracer_entry`. Решить: починить trace ИЛИ static-only + явная opt-in заглушка с понятной ошибкой.
- **G1.2** `integrity_checks` (phantom_handlers, declared_capabilities) — Vigil-специфичные (INTERFACE.operator). Отключить в standalone (gate-registry skip, как дропнули FOC) → убирает ложные HIGH.
- **G1.3** Producer-метки `BRAIN.autoforensics.*` → `cortex_map_builder.*` (map_models/map_storage/cli_entry).
- **G1.4** ПОЛНЫЙ аудит cluster-ссылок (не только `import` — argv/importlib/строки/docstrings). Классифицировать: functional → починить; provenance-docstring → оставить/переформулировать.
- **Verify:** forensic на не-Vigil проекте без `declared_vs_actual`/INTERFACE-findings; честный grep.

### G2 — Завершить непроверенные свойства  [investigation + фиксы]
- **G2.1 Детерминизм:** прогон ×2, diff байт-в-байт; починить источники (sorted-вывод, PYTHONHASHSEED, glob-order).
- **G2.2 Инкрементальность:** замерить cold/warm; подтвердить on-disk L2-cache работает cross-process; инвалидация по mtime/hash. Документировать.
- **G2.3 Job-персистентность:** сверить с DOCR `background_runner`; портировать disk-backed результаты (jobs/находки переживают рестарт MCP).
- **G2.4 Конфигурируемость:** портировать из DOCR — `disabled_gates`, severity-config, регистрация кастомных гейтов (G-A уже дал `gate_profile.json` auto-load).

### G3 — Output + UX  [usability; был прерван G-C]
- **G3.1** Summary-first: `get_*_results` по умолчанию сводка (counts + top-N HIGH с file:line); drill-down по `view=full`/`severity=`/`check_id=`/`map=`/pagination.
- **G3.2** Auto-path: `path` опционален → корень проекта (git/pyproject вверх от cwd), иначе cwd; вернуть `resolved_path`.
- **G3.3 (опц.)** channels-push находок (изначальное пожелание «сами отправляли находки»).

### G4 — FP до ~10%  [качество сигнала]
- **G4.1** Дефолтный `gate_profile.json` для cortex (пороги size/complexity/nesting выше → меньше size-шума).
- **G4.2** Замерить FP на реальных проектах (не self-audit), подтвердить ~10%.

### G5 — Реальная интеграция и проверка пригодности  [acceptance]
- **G5.1** `claude mcp add` обоих серверов — реально подключить.
- **G5.2** Прогон на 2-3 реальных проектах (Python + multi-lang): метрики время/память/токены-вывода/полезность/удобство.
- **G5.3** Зафиксировать метрики до/после.

### G6 — Финализация  [ship-ready]
- **G6.1** README честный (безопасность, конфигурируемость, persistence, capability-матрица).
- **G6.2** CI реально прогнать (не только yaml) на OS×Python.
- **G6.3** ПРАВИЛЬНЫЙ финальный forensics gate (полный grep, self-audit с профилем).
- **G6.4** Все тесты зелёные.

### G7 — Публикация  [ТОЛЬКО по команде Julio]
- PyPI / публичный remote — outbound + необратимо. Требует явной команды.

---

## Исполнение
- **Урок race:** пишущие субагенты — `isolation:worktree` ИЛИ строго последовательно (НЕ параллельно на одном дереве). Read-only investigation — параллельно OK.
- Я оркестратор+валидатор: валидирую КАЖДЫЙ коммит сам (scope+diff+прогон+grep), не доверяю summary.
- Resource-light: без `-n auto`, целевые тесты, полный suite редко+фоном.
- Classifier (Bash/Agent) может временно лежать — read-only (Read/Grep) всегда доступны.

## Порядок (зависимости)
G1 → (G2 ∥ G3 ∥ G4) → G5 → G6 → G7. G1 первым (корректность). G4 после G1.2 (integrity_checks убраны). G5 после G1-G4.
