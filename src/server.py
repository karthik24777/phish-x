"""
PHISH-X — local protection service.

Run:   python server.py        (listens on 127.0.0.1:8765)

The browser extension (and later a mobile app) talk to this service:
    POST /check    {"url": "..."}  -> fast ML verdict + evidence
    POST /sandbox  {"url": "..."}  -> deeper page inspection + combined verdict
    GET  /health
"""

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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

HOSTED = os.environ.get("PHISHX_HOSTED") == "1"      # shared public deployment: privacy + abuse limits on
LIMITS = {"/check": 40, "/sandbox": 6, "/agent": 6, "/email": 20}   # requests per minute per client (hosted only)
_hits = defaultdict(deque)


@app.middleware("http")
async def hosted_guard(request: Request, call_next):
    if HOSTED and request.method == "POST":
        limit = LIMITS.get(request.url.path)
        if limit:
            ip = (request.headers.get("x-forwarded-for") or request.client.host or "?").split(",")[0].strip()
            q = _hits[(ip, request.url.path)]
            now = time.time()
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= limit:
                return JSONResponse({"detail": "Too many requests, please wait a minute."}, status_code=429)
            q.append(now)
            if len(_hits) > 5000:
                _hits.clear()
        if int(request.headers.get("content-length") or 0) > 300_000:
            return JSONResponse({"detail": "Request too large."}, status_code=413)
    return await call_next(request)


stats = {"checked": 0, "blocked": 0, "sandboxed": 0, "started": time.time()}
recent = deque(maxlen=200)   # in memory only; never written to disk


class UrlIn(BaseModel):
    url: str
    replay: bool = False


class EmailIn(BaseModel):
    raw: str


def _log(kind, url, r):
    if HOSTED:        # a public server must never keep or show other people's links
        return
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
    r = core.full_report(url, body.replay)
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
    if not HOSTED:
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


@app.get("/replay.js")
def replay_js():
    return FileResponse(Path(__file__).resolve().parent / "replay.js", media_type="application/javascript")


@app.get("/guard")
def guard():
    return FileResponse(Path(__file__).resolve().parent / "guard.html")


@app.get("/logo.png")
def logo():
    return FileResponse(Path(__file__).resolve().parent / "assets" / "logo.png")


@app.get("/")
def dashboard():
    return FileResponse(Path(__file__).resolve().parent / "dashboard.html")


if __name__ == "__main__":
    uvicorn.run(app, host=os.environ.get("PHISHX_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8765")), log_level="warning")
