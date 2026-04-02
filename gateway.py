"""OpenAudit Gateway — HTTP API for security scanning."""
import os
import time
import uuid
import logging
from pathlib import Path
from typing import Dict, List, Any

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
import uvicorn
import yaml

from openaudit.scanner import Scanner, Finding
from openaudit.report import generate_html, generate_sarif

logger = logging.getLogger("openaudit.gateway")

APP_VERSION = "0.1.0"
ENV = os.getenv("OPENAUDIT_ENV", "production")
RULES_PATH = Path(os.getenv("OPENAUDIT_RULES", "src/openaudit/data/rules.yaml"))

# Initialize scanner
scanner = Scanner(RULES_PATH)

# HTTP metrics
metrics = {"requests_total": 0, "requests_failed": 0, "scans_performed": 0}

def create_app() -> FastAPI:
    app = FastAPI(title="OpenAudit API", version=APP_VERSION, docs_url="/docs")

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        start = time.time()
        metrics["requests_total"] += 1
        try:
            resp = await call_next(request)
            elapsed = time.time() - start
            logger.info("http completed", extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": resp.status_code,
                "ms": int(elapsed*1000)
            })
            resp.headers["X-Request-ID"] = request_id
            return resp
        except Exception as exc:
            metrics["requests_failed"] += 1
            logger.error("http failed", extra={"request_id": request_id, "error": str(exc)})
            raise

    @app.get("/health")
    async def health():
        return {"status": "ok", "timestamp": time.time(), "version": APP_VERSION, "environment": ENV}

    @app.get("/metrics")
    async def get_metrics():
        return metrics

    @app.post("/scan")
    async def scan_agent(
        agent: UploadFile = File(...),
        format: str = Form("json")  # json, sarif, html
    ):
        """Upload an agent YAML config and get audit report."""
        try:
            content = await agent.read()
            config = yaml.safe_load(content)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

        findings: List[Finding] = scanner.scan(config)
        metrics["scans_performed"] += 1

        if format == "json":
            return {"agent": agent.filename, "findings": [f.dict() for f in findings]}
        elif format == "sarif":
            sarif_path = Path("/tmp/report.sarif")
            generate_sarif(findings, agent.filename, sarif_path)
            sarif_content = sarif_path.read_text()
            return PlainTextResponse(sarif_content, media_type="application/sarif+json")
        elif format == "html":
            html_path = Path("/tmp/report.html")
            generate_html(findings, agent.filename, html_path)
            html_content = html_path.read_text()
            return HTMLResponse(html_content)
        else:
            raise HTTPException(status_code=400, detail="format must be json, sarif, or html")

    @app.get("/rules")
    async def list_rules():
        """List loaded rules."""
        return {"rules": scanner.rules}

    return app

app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    uvicorn.run("gateway:app", host="0.0.0.0", port=int(os.getenv("OPENAUDIT_PORT", 8000)), reload=ENV=="development")
