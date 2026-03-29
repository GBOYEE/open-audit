"""Report generators."""
import json
from pathlib import Path
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>OpenAudit Report</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    .critical { color: #d32f2f; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .low { color: #388e3c; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f4f4f4; }
  </style>
</head>
<body>
  <h1>OpenAudit Report</h1>
  <p><strong>Agent file:</strong> {{ agent_path }}</p>
  <p><strong>Total findings:</strong> {{ findings|length }}</p>
  {% if findings %}
  <table>
    <tr><th>Severity</th><th>Rule ID</th><th>Message</th><th>Suggestion</th></tr>
    {% for f in findings %}
    <tr class="{{ f.severity }}">
      <td>{{ f.severity }}</td>
      <td>{{ f.rule_id }}</td>
      <td>{{ f.message }}</td>
      <td>{{ f.suggestion }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No issues found. 🎉</p>
  {% endif %}
</body>
</html>
"""

def generate_html(findings, agent_path: str, output_path: Path):
    template = Template(HTML_TEMPLATE)
    html = template.render(findings=findings, agent_path=agent_path)
    output_path.write_text(html)

def generate_sarif(findings, agent_path: str, output_path: Path):
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OpenAudit", "version": "0.1.0"}},
            "results": [
                {
                    "ruleId": f.rule_id,
                    "level": f.severity,
                    "message": {"text": f.message},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": agent_path}, "region": {"startLine": 1}}}]
                }
                for f in findings
            ]
        }]
    }
    output_path.write_text(json.dumps(sarif, indent=2))
