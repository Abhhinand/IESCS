"""
main.py
FastAPI backend for the Autonomous Deception Intelligence Platform.

Endpoints:
  GET  /api/canary/{token_id}        -> the trap itself; any hit is a real event
  POST /api/tokens/pdf                -> generate a new trackable PDF honeytoken
  POST /api/tokens/env                -> generate a new bait .env file
  POST /api/tokens/endpoint           -> register a fake admin endpoint token
  GET  /api/tokens                    -> list all honeytokens
  GET  /api/events                    -> list telemetry events (for dashboard)
  GET  /api/events/{event_id}         -> event detail
  POST /api/events/{event_id}/status  -> analyst approves/dismisses an action
  GET  /health                        -> liveness check
"""

import asyncio
import os
from collections import defaultdict
from datetime import datetime, timedelta

from dotenv import load_dotenv

# Load variables from a .env file in the project root into the environment
# automatically, so you don't have to manually export/set them in every
# new terminal session before starting the server.
# override=True ensures .env always wins over any stale value left behind
# in this terminal session from an earlier manual `set VAR=...` command -
# without this, an old leftover env var silently takes priority and .env
# edits appear to have no effect.
_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(_ENV_PATH, override=True)

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import database as db
from honeytoken_generator import (
    generate_pdf_token, generate_env_token, generate_api_endpoint_token,
    generate_source_code_token, generate_cloud_credentials_token,
)
from enrichment import enrich_ip, is_known_benign
from agents import run_triage_agent

app = FastAPI(title="Deception Intelligence Platform API")

if os.environ.get("GROQ_API_KEY"):
    print("[startup] GROQ_API_KEY loaded - AI triage enabled.")
else:
    print("[startup] WARNING: GROQ_API_KEY not found. Check your .env file - "
          "AI triage will fail and fall back to MEDIUM/manual review for every event.")


# Streamlit dashboard runs on a different port/process, so allow it through.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory rolling counter of hits per IP, used for the "Behavioral Velocity
# Analysis" filtering stage described in Q2. Resets are lazy (time-windowed).
_ip_hit_log = defaultdict(list)  # ip -> list[datetime]


@app.on_event("startup")
def on_startup():
    db.init_db()


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


# ---------------------- Honeytoken generation ----------------------

class TokenRequest(BaseModel):
    bait_name: str | None = None
    location_hint: str | None = None


@app.post("/api/tokens/pdf")
def create_pdf_token(req: TokenRequest):
    kwargs = {}
    if req.bait_name:
        kwargs["bait_name"] = req.bait_name
    if req.location_hint:
        kwargs["location_hint"] = req.location_hint
    result = generate_pdf_token(**kwargs)
    return result


@app.post("/api/tokens/env")
def create_env_token(req: TokenRequest):
    kwargs = {}
    if req.bait_name:
        kwargs["bait_name"] = req.bait_name
    if req.location_hint:
        kwargs["location_hint"] = req.location_hint
    result = generate_env_token(**kwargs)
    return result


@app.post("/api/tokens/endpoint")
def create_endpoint_token(req: TokenRequest):
    kwargs = {}
    if req.bait_name:
        kwargs["bait_name"] = req.bait_name
    if req.location_hint:
        kwargs["location_hint"] = req.location_hint
    result = generate_api_endpoint_token(**kwargs)
    return result


@app.post("/api/tokens/source-code")
def create_source_code_token(req: TokenRequest):
    kwargs = {}
    if req.bait_name:
        kwargs["bait_name"] = req.bait_name
    if req.location_hint:
        kwargs["location_hint"] = req.location_hint
    result = generate_source_code_token(**kwargs)
    return result


@app.post("/api/tokens/cloud-credentials")
def create_cloud_credentials_token(req: TokenRequest):
    kwargs = {}
    if req.bait_name:
        kwargs["bait_name"] = req.bait_name
    if req.location_hint:
        kwargs["location_hint"] = req.location_hint
    result = generate_cloud_credentials_token(**kwargs)
    return result


@app.get("/api/tokens")
def get_tokens():
    return db.list_tokens()


# ---------------------- The trap itself ----------------------

def _record_hit(ip: str) -> int:
    """Track hits per IP over a rolling 60-minute window; return recent count."""
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=60)
    hits = [t for t in _ip_hit_log[ip] if t > window_start]
    hits.append(now)
    _ip_hit_log[ip] = hits
    return len(hits)


async def _process_event_pipeline(event_id: int, token: dict, ip: str, user_agent: str,
                                   request_path: str, recent_count: int):
    """
    Background task: runs AFTER the webhook has already returned a response
    to whoever/whatever hit the canary. This keeps ingestion latency low
    (per Q1's decoupling rationale) even though we're using SQLite + a
    synchronous-feeling LLM call here for the demo. In the production
    scaling path (Q3) this becomes a Celery/RabbitMQ worker job instead
    of an in-process background task.
    """
    geo = await enrich_ip(ip)
    benign = is_known_benign(user_agent)

    triage = await run_triage_agent(
        token_type=token["token_type"],
        bait_name=token["bait_name"],
        ip_address=ip,
        geo=geo,
        user_agent=user_agent,
        request_path=request_path,
        method="GET",
        recent_count=recent_count,
        is_benign=benign,
    )

    db.update_event_enrichment(
        event_id,
        geo=geo,
        intent_score=triage["intent_score"],
        severity=triage["severity"],
        triage_summary=triage["triage_summary"],
        proposed_action=triage["proposed_action"],
    )


@app.get("/api/canary/{token_id}")
@app.post("/api/canary/{token_id}")
async def canary_hit(token_id: str, request: Request, background_tasks: BackgroundTasks):
    """
    The actual honeytoken trigger. Anyone/anything requesting this URL
    (via the embedded PDF link, the fake .env INTEGRITY_CHECK_URL, or a
    probe of the fake admin endpoint) is, by definition, someone with no
    legitimate reason to know this URL exists.
    """
    token = db.get_token(token_id)
    if not token:
        # Unknown token id - don't leak information, just 404 like a real route would.
        raise HTTPException(status_code=404, detail="Not found")

    ip = request.client.host if request.client else "unknown"
    # Respect X-Forwarded-For if behind a proxy/load balancer (Q3 scaling path).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "")
    headers = dict(request.headers)

    event_id = db.insert_event(
        token_id=token_id,
        ip_address=ip,
        user_agent=user_agent,
        headers=headers,
        request_path=str(request.url.path),
        method=request.method,
    )

    recent_count = _record_hit(ip)

    # Fire enrichment + AI triage asynchronously so the trap itself
    # responds instantly and never tips off the attacker via latency.
    background_tasks.add_task(
        _process_event_pipeline, event_id, token, ip, user_agent,
        str(request.url.path), recent_count,
    )

    # Return an innocuous response so the interaction looks like a normal
    # (if slightly broken) internal verification page, not a security trap.
    return JSONResponse(
        status_code=200,
        content={"status": "verified", "message": "Access logged. You may proceed."},
    )


# ---------------------- Dashboard-facing API ----------------------

@app.get("/api/events")
def get_events(limit: int = 200):
    return db.list_events(limit=limit)


@app.get("/api/events/{event_id}")
def get_event(event_id: int):
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


class StatusUpdate(BaseModel):
    status: str  # NEW / REVIEWED / ACTIONED / DISMISSED


@app.post("/api/events/{event_id}/status")
def set_event_status(event_id: int, update: StatusUpdate):
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    valid = {"NEW", "REVIEWED", "ACTIONED", "DISMISSED"}
    if update.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    db.update_event_status(event_id, update.status)
    return {"event_id": event_id, "status": update.status}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
