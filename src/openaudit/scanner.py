"""Scanner engine: load rules, validate agent config."""
import yaml
from pathlib import Path
from typing import List, Dict, Any
from pydantic import BaseModel, ValidationError

class Finding(BaseModel):
    rule_id: str
    severity: str  # critical, high, medium, low
    message: str
    path: str  # e.g., "tools.0.name"
    suggestion: str = ""

class RuleSet(BaseModel):
    rule_id: str
    description: str
    severity: str
    # Condition: a Python expression evaluated against the config? For MVP, simple patterns.
    pattern: Dict[str, Any]  # e.g., {"field": "tools", "contains": "shell"}
    suggestion: str = ""

class Scanner:
    def __init__(self, rules_file: Path):
        self.rules = self._load_rules(rules_file)

    def _load_rules(self, path: Path) -> List[RuleSet]:
        with open(path) as f:
            data = yaml.safe_load(f)
        return [RuleSet(**r) for r in data.get("rules", [])]

    def scan(self, config: Dict[str, Any]) -> List[Finding]:
        findings = []
        for rule in self.rules:
            # Simple pattern matching: check if config contains a forbidden value at a given path
            # pattern may have keys: field (dot path), value, contains, regex
            pat = rule.pattern
            field = pat.get("field")
            if field:
                # Navigate dot path
                parts = field.split(".")
                val = config
                for p in parts:
                    if isinstance(val, dict):
                        val = val.get(p)
                    else:
                        val = None
                        break
                if val is None:
                    continue
                # Condition checks
                if "value" in pat and val == pat["value"]:
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=f"Field '{field}' has forbidden value: {val}",
                        path=field,
                        suggestion=rule.suggestion
                    ))
                if "contains" in pat and isinstance(val, (list, str)):
                    if pat["contains"] in val:
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            message=f"Field '{field}' contains forbidden item: {pat['contains']}",
                            path=field,
                            suggestion=rule.suggestion
                        ))
                if "regex" in pat and isinstance(val, str):
                    import re
                    if re.search(pat["regex"], val):
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            message=f"Field '{field}' matches forbidden pattern: {pat['regex']}",
                            path=field,
                            suggestion=rule.suggestion
                        ))
        return findings
