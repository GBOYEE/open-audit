# 01-01: Define Agent Schema Rules

**Epic:** Core Scanner

## Goal

Specify what constitutes safe vs. dangerous agent configuration (tools, permissions, LLM settings).

## Acceptance Criteria

- `rules.yaml` with patterns:
  - banned_tools: ["shell", "execute_code"] (unless explicitly allowed)
  - required_fields: ["name", "tools"]
  - max_tools: 20
  - required_approval: true for file_write
- Documentation explaining each rule
- Tests: sample configs should pass/fail accordingly

## Tasks

1. Research common agent security issues (CVE, OWASP for AI)
2. Draft rule set in YAML
3. Write Python validator that reads rules and checks agent config
4. Add unit tests for valid/invalid configs

## Dependencies

None

## Time Estimate

3 hours
