"""
PHISH-X — local protection service.

Run:   python server.py        (listens on 127.0.0.1:8765)

The browser extension (and later a mobile app) talk to this service:
    POST /check    {"url": "..."}  -> fast ML verdict + evidence
    POST /sandbox  {"url": "..."}  -> deeper page inspection + combined verdict
    GET  /health
"""

import json
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

import core
import agent
import email_analyzer

REPORTS = Path(__file__).resolve().parent.parent / "reports"

app = FastAPI(title="PHISH-X Protection Service", version="0.2")

# The service only listens on localhost; extension pages call it from
# chrome-extension:// origins, so CORS must allow them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

stats = {"checked": 0, "blocked": 0, "sandboxed": 0, "started": time.time()}
recent = deque(maxlen=200)   # in memory only; never written to disk


class UrlIn(BaseModel):
    url: str


class EmailIn(BaseModel):
    raw: str


def _log(kind, url, r):
    recent.appendleft({"t": time.strftime("%H:%M:%S"), "kind": kind, "url": url[:160],
                       "verdict": r["verdict"], "score": r["risk_score"]})


@app.get("/health")
def health():
    return {"status": "ok", "service": "phish-x", "stats": stats,
            "dynamic_sandbox": core.SANDBOX_MODE != "static" and core.dyn.available()}


@app.post("/check")
def check(body: UrlIn):
    url = body.url.strip()
    stats["checked"] += 1
    result = dict(core.assess(url))
    if result["verdict"] == "PHISHING":
        stats["blocked"] += 1
    _log("check", url, result)
    return result


@app.post("/sandbox")
def sandbox(body: UrlIn):
    url = body.url.strip()
    stats["sandboxed"] += 1
    r = core.full_report(url)
    _log("sandbox", url, r)
    return r


@app.post("/agent")
def agent_endpoint(body: UrlIn):
    r = agent.investigate(body.url.strip())
    _log("agent", body.url, r)
    return r


@app.post("/email")
def email_endpoint(body: EmailIn):
    r = email_analyzer.analyze(body.raw)
    recent.appendleft({"t": time.strftime("%H:%M:%S"), "kind": "email", "url": (r.get("subject") or "(no subject)")[:120],
                       "verdict": r["verdict"], "score": r["risk_score"]})
    return r


def _load(name):
    p = REPORTS / name
    return json.loads(p.read_text()) if p.exists() else None


@app.get("/api/summary")
def summary():
    camp = _load("campaigns.json")
    return {"stats": stats, "recent": list(recent)[:25], "metrics": _load("metrics.json"),
            "adversarial": _load("adversarial.json"), "email_metrics": _load("email_metrics.json"), "agent_benchmark": _load("agent_benchmark.json"),
            "campaigns": (camp["campaigns"][:12] if camp else []), "campaign_total": len(camp["campaigns"]) if camp else 0}


@app.get("/logo.png")
def logo():
    return FileResponse(Path(__file__).resolve().parent / "assets" / "logo.png")


@app.get("/")
def dashboard():
    return FileResponse(Path(__file__).resolve().parent / "dashboard.html")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
