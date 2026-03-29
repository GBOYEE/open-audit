# 01-03: Generate SARIF/HTML Reports

**Epic:** Core Scanner

## Goal

Export scan results in industry formats for CI integration.

## Acceptance Criteria

- `openaudit scan --output report.sarif` produces SARIF v2.1.0 JSON
- `--output report.html` produces styled HTML with tables of findings
- HTML includes counts (critical, high, medium, low) and rule descriptions
- SARIF includes locations (file, line) when available
- Example reports committed to `examples/`

## Tasks

1. Research SARIF schema; create serializer
2. Build HTML template (Jinja2) with Tailwind styling (reuse claw-ui?)
3. Add `--format` option to CLI (auto-detects by extension)
4. Test with large config to ensure performance
5. Document formats in README

## Dependencies

01-02

## Time Estimate

5 hours
