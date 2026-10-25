import os
import json
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from config import PROFILE, MAX_BODY_SIZE
from canonical import digest
from database import init_db, get_run, save_run, update_run, get_receipt, save_receipt
from telemetry import parse_traceparent
from planner import plan_incident, validate_plan
from state_machine import initialize_incident_run, process_receipts_state_machine, sanitize_public_state
from schemas import validate_incident_request_json, validate_receipt_request_json

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield

app = FastAPI(
    title="Observable Incident Agent",
    description="Observable Incident Triage agent conforming to ga5-incident-agent/v2",
    version="0.2.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def check_payload_size(request: Request, call_next):
    """Enforce payload size limits to protect against memory exhaustion."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Payload too large. Maximum allowed size is {MAX_BODY_SIZE} bytes"}
        )
    return await call_next(request)

@app.get("/")
async def root():
    return {
        "service": "observable-incident-agent",
        "profile": PROFILE,
        "status": "ready"
    }

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@app.post("/v2/incidents")
async def create_incident(request: Request):
    """POST /v2/incidents: Accept incident case, diagnose using AI, and dispatch diagnostics."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Strict schema validation
    validate_incident_request_json(body)

    run_id = body["runId"]
    req_hash = digest(body)

    # Concurrency and idempotency check
    existing = get_run(run_id)
    if existing:
        prior_hash, prior_state = existing
        if prior_hash != req_hash:
            raise HTTPException(
                status_code=409,
                detail="runId already exists with different content"
            )
        # Replaying identical request returns stored result without another AI call or duplicate dispatches
        return JSONResponse(content=sanitize_public_state(prior_state))

    # Incoming trace context continuation
    tp_header = request.headers.get("traceparent")
    incoming_trace_info = parse_traceparent(tp_header)

    # Fresh AI model planning call
    try:
        raw_plan = await plan_incident(body)
        plan = validate_plan(raw_plan, body)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Incident planning failed: {str(exc)}")

    # Initialize state machine & OTLP traces
    state = initialize_incident_run(
        run_id=run_id,
        plan=plan,
        body=body,
        req_hash=req_hash,
        incoming_trace_info=incoming_trace_info
    )

    save_run(run_id, req_hash, state)
    return JSONResponse(content=sanitize_public_state(state), status_code=200)

@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    """GET /v2/incidents/{runId}: Retrieve current incident state, dispatches, approvals, logs, and traces."""
    existing = get_run(run_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    _, state = existing
    return JSONResponse(content=sanitize_public_state(state), status_code=200)

@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipts(run_id: str, request: Request):
    """POST /v2/incidents/{runId}/receipts: Process diagnostic outcomes, handle retries, timeouts, and approval gating."""
    existing = get_run(run_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    validate_receipt_request_json(body)

    receipt_id = body["receiptId"]
    receipt_hash = digest(body)

    # Receipt idempotency and conflict check
    prior_receipt = get_receipt(run_id, receipt_id)
    if prior_receipt:
        prior_hash, prior_response = prior_receipt
        if prior_hash != receipt_hash:
            raise HTTPException(
                status_code=409,
                detail="receiptId already exists with different content"
            )
        # Replaying identical receipt returns identical stored response
        return JSONResponse(content=sanitize_public_state(prior_response))

    # Incoming trace context continuation if passed on receipt request
    tp_header = request.headers.get("traceparent")
    incoming_trace_info = parse_traceparent(tp_header)

    # Load latest state and apply state machine transitions
    _, current_state = existing
    updated_state = process_receipts_state_machine(current_state, body, incoming_trace_info=incoming_trace_info)

    # Persist updated run state and receipt record
    update_run(run_id, updated_state)
    public_response = sanitize_public_state(updated_state)
    save_receipt(run_id, receipt_id, receipt_hash, public_response)

    return JSONResponse(content=public_response, status_code=200)
