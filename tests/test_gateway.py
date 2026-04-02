import pytest
from fastapi.testclient import TestClient
from gateway import create_app, scanner

client = TestClient(create_app())

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data

def test_metrics():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "requests_total" in data
    assert "scans_performed" in data

def test_rules_list():
    resp = client.get("/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert "rules" in data
    assert len(data["rules"]) >= 1  # at least default rules

def test_scan_json():
    yaml_content = b"""
name: test_agent
tools:
  - shell
  - code_exec
"""
    resp = client.post("/scan", files={"agent": ("agent.yaml", yaml_content)}, data={"format": "json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent"] == "agent.yaml"
    assert isinstance(data["findings"], list)
    # Should flag shell and code_exec as banned
    findings = data["findings"]
    rule_ids = [f["rule_id"] for f in findings]
    assert "banned_tool_shell" in rule_ids
    assert "banned_tool_code_exec" in rule_ids

def test_scan_sarif():
    yaml_content = b"""
name: test_agent
tools:
  - shell
"""
    resp = client.post("/scan", files={"agent": ("agent.yaml", yaml_content)}, data={"format": "sarif"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/sarif+json")
    data = resp.json()
    assert "runs" in data

def test_scan_html():
    yaml_content = b"""
name: test_agent
tools:
  - shell
"""
    resp = client.post("/scan", files={"agent": ("agent.yaml", yaml_content)}, data={"format": "html"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/html"
    assert b"OpenAudit Report" in resp.content

def test_scan_invalid_yaml():
    yaml_content = b"this is not yaml :"
    resp = client.post("/scan", files={"agent": ("bad.yaml", yaml_content)})
    assert resp.status_code == 400
    assert "Invalid YAML" in resp.json()["detail"]
