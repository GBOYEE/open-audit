# Roadmap: OpenAudit

## Phases

- [ ] **Phase 1: Core Scanner** — Tool permission analysis, config linting
- [ ] **Phase 2: Red‑Team Engine** — Adversarial prompt generation, jailbreak detection
- [ ] **Phase 3: Bias Detector** — Decision log analysis, fairness metrics
- [ ] **Phase 4: Reporting & Integration** — Reports, CI plugin, dashboard

### Phase 1 (v0.5.0)

Plans:
- 01-01: Define agent schema rules (allowed tools, dangerous patterns)
- 01-02: Implement scanner CLI (`openaudit scan <agent.yaml>`)
- 01-03: Generate SARIF/HTML reports
- 01-04: Publish as PyPI package; write docs

### Phase 2 (v0.6.0)

Plans:
- 02-01: Build red‑team prompt library (jailbreak templates)
- 02-02: Run agent in sandbox, detect successful exploits
- 02-03: Score risk severity (CVSS‑like)
- 02-04: Add mitigation suggestions

### Phase 3 (v0.7.0)

Plans:
- 03-01: Collect agent decisions (log format)
- 03-02: Compute fairness metrics (demographic parity, equal opportunity)
- 03-03: Visualize bias in UI charts
- 03-04: Add differential privacy checks

### Phase 4 (v0.8.0 → v1.0.0)

Plans:
- 04-01: Create GitHub Action (run on push)
- 04-02: Build admin dashboard (Streamlit or FastAPI)
- 04-03: Write grant reports; create case studies
- 04-04: Release 1.0.0; community outreach

**Total:** 16 plans
