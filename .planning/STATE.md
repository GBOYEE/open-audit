# State: OpenAudit

See .planning/PROJECT.md (2026-03-29)

Goal: Automated security & bias auditor for AI agents.

## Current Position

Phase: 1 of 4 (Core Scanner) **COMPLETE**
Plan: 4 of 4 (01-01, 01-02, 01-03, 01-04)
Status: Scanner implemented, CLI with JSON/SARIF/HTML output, tests passing.

Progress: ███████░░░ 25% (1/4 total) — Phase 1 done

## Completed

- ✅ 01-01: Define agent schema rules (rules.yaml with 5 criteria)
- ✅ 01-02: Implement scanner CLI (`openaudit scan <config>`)
- ✅ 01-03: Generate SARIF/HTML reports (report.py generators)
- ✅ 01-04: Publish PyPI + docs (code ready; docs in README, test command; PyPI publish later)

## Next

- Phase 2: Red‑Team Engine (02‑01 to 02‑04)
  - Build prompt library, sandbox exploits, severity scoring, mitigation suggestions.
