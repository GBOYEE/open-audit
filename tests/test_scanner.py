"""Tests for OpenAudit scanner and reporting."""
import pytest
import yaml
from pathlib import Path
from openaudit.scanner import Scanner, Finding

def test_scanner_detects_banned_tool():
    config = {
        "name": "TestAgent",
        "tools": ["shell", "search"]
    }
    scanner = Scanner(Path(__file__).parent.parent / "src" / "openaudit" / "data" / "rules.yaml")
    findings = scanner.scan(config)
    assert any(f.rule_id == "banned_tool_shell" for f in findings)

def test_scanner_missing_name():
    config = {"tools": []}
    scanner = Scanner(Path(__file__).parent.parent / "src" / "openaudit" / "data" / "rules.yaml")
    findings = scanner.scan(config)
    assert any(f.rule_id == "missing_name" for f in findings)

def test_scanner_clean_passes():
    config = {
        "name": "CleanAgent",
        "tools": ["search", "read_file"],
        "require_approval": True
    }
    scanner = Scanner(Path(__file__).parent.parent / "src" / "openaudit" / "data" / "rules.yaml")
    findings = scanner.scan(config)
    # Should not have any findings (maybe low on file_write rule not triggered)
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) == 0
