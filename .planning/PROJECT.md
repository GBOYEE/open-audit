# OpenAudit — Automated Security & Bias Auditor for AI Agents

**Problem:** AI agents (like ChatGPT plugins, AutoGPT) can execute arbitrary code, leak data, or exhibit harmful bias. No easy tool exists to automatically scan agent configurations and behavior for security risks.

**Solution:** OpenAudit — a framework that:
- Analyzes agent tool definitions for dangerous permissions (shell access, file write)
- Runs red‑team simulations (adversarial prompts) to test for jailbreaks
- Checks decision logs for bias patterns (demographic parity)
- Produces compliance‑ready reports (SOC2, ISO 27001 mappings)

**Target grants:** Ethereum Foundation (secure smart contracts & agents), Gitcoin (security), Mozilla Technology Fund (trustworthy AI), Fast Grants (security track).

**Success (12 months):**
- 50+ open‑source agents scanned
- 10 security vulnerabilities found and responsibly disclosed
- 500+ GitHub stars
- Integrated into agent‑core CI as plugin

**Tech:** Python, agent‑core plugins, LLM red‑team (using phi3:mini), PostgreSQL for findings, FastAPI UI.
