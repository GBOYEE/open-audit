"""CLI entry point for openaudit."""
import sys
import json
import yaml
from pathlib import Path
from .scanner import Scanner, Finding

def main():
    if len(sys.argv) < 2:
        print("Usage: openaudit <config.yaml> [--format json|sarif|html]")
        sys.exit(1)

    config_path = Path(sys.argv[1])
    if not config_path.exists():
        print(f"Error: file not found: {config_path}")
        sys.exit(1)

    fmt = "json"
    if "--format" in sys.argv:
        idx = sys.argv.index("--format")
        if idx + 1 < len(sys.argv):
            fmt = sys.argv[idx + 1]

    # Load agent config
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Load rules from default location (package data)
    rules_path = Path(__file__).parent / "data" / "rules.yaml"
    scanner = Scanner(rules_path)
    findings = scanner.scan(config)

    # Output
    if fmt == "json":
        out = [f.dict() for f in findings]
        print(json.dumps(out, indent=2))
    elif fmt == "sarif":
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "OpenAudit", "version": "0.1.0"}},
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": f.severity,
                        "message": {"text": f.message},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": config_path.name}, "region": {"startLine": 1}}}]
                    }
                    for f in findings
                ]
            }]
        }
        print(json.dumps(sarif, indent=2))
    else:
        print(f"Format {fmt} not implemented yet")
        sys.exit(1)

    # Exit code: 0 if no findings, else 1
    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
