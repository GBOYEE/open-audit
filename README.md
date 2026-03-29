# OpenAudit

Security & bias auditor for AI agents.

```
openaudit scan agent.yaml --format json
openaudit scan agent.yaml --format sarif > report.sarif
openaudit scan agent.yaml --format html > report.html
```

## Install

```bash
pip install -e .
```

## Rules

Default rules in `src/openaudit/data/rules.yaml`:

- `banned_tool_shell`: disallows `shell` tool
- `banned_tool_code_exec`: disallows `execute_code`
- `missing_name`: agent must have a name
- `file_write_requires_approval`: file_write should require approval
- `too_many_tools`: more than 20 tools is risky (partial)

## Custom rules

Write your own YAML with same structure and point to it:

```
openaudit scan agent.yaml --rules custom-rules.yaml
```

## Roadmap

Phases:

1. Core Scanner (done)
2. Red‑Team Engine
3. Bias Detector
4. Reporting & Integration

## Reporting

Outputs JSON, SARIF (CI integration), and HTML (human‑readable). SARIF can be uploaded to GitHub Advanced Security or CodeQL.
