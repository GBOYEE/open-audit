# 01-02: Implement Scanner CLI

**Epic:** Core Scanner

## Goal

Create `openaudit scan <config.yaml>` command that outputs pass/fail and findings.

## Acceptance Criteria

- `openaudit` entry point (console_scripts)
- Loads agent config (YAML) and rules
- Runs all checks; exits with code 0 if pass, 1 if fail
- Prints human‑readable summary; `--format json` for machine output
- Returns list of violated rules with line numbers if possible

## Tasks

1. Set up package structure (`openaudit/` with `__main__.py`)
2. Implement rule engine: load rules, iterate over config
3. Add findings collector with severity levels
4. Implement CLI using Click or argparse
5. Write tests (invoke CLI on sample configs)
6. Add to `README` usage example

## Dependencies

01-01

## Time Estimate

6 hours
