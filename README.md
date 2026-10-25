# Observable Incident Triage Agent (`ga5-incident-agent/v2`)

A complete, production-ready, and submission-verified backend service for the IIT Madras BS Data Science assignment: **"Observable Incident Triage: Diagnose Before Acting"** (4 Marks).

---

## 1. Architecture & Design

This service implements a safe, receipt-driven, observable incident remediation engine adhering to the `ga5-incident-agent/v2` specification:

```
[Incoming Incident Request]
           │
           ▼ (POST /v2/incidents)
┌──────────────────────────────────────────────┐
│  1. Request Validation & Privacy Filter      │  -> Strips 'sensitive' and 'doNotExport'
│  2. SQLite Idempotency & Conflict Check      │  -> HTTP 409 on altered replay
│  3. W3C traceparent Context Continuation     │
│  4. Safe AI Planning (OpenRouter / OpenAI)   │  -> Proposes Root Cause & Diagnostics
│  5. Diagnostic Dispatch & OTLP Telemetry     │
└──────────────────────────────────────────────┘
           │
           ▼ Status: "waiting" (Diagnostic Phase)
[Authoritative Receipts & Outcomes]
           │
           ▼ (POST /v2/incidents/{runId}/receipts)
┌──────────────────────────────────────────────┐
│  State Machine & Safety Engine:              │
│  • 503 Transient Error:                      │
│      -> Exactly 1 retry (stable IDs, new span)│
│  • Timeout Outcome:                          │
│      -> Suppresses dependent effects         │
│  • Diagnostics Succeeded:                    │
│      -> Selects 1 justified effect tool      │
│  • Destructive Action (rollback, disable):   │
│      -> Requires approval with SHA-256 digest│
│  • Approved Destructive Action:              │
│      -> Dispatches effect tool               │
│  • Effect Succeeded:                         │
│      -> Status: "resolved"                   │
└──────────────────────────────────────────────┘
           │
           ▼
[State Persisted in SQLite & OTLP Traces Correlated]
```

### File Structure
- `app.py`: FastAPI server routes (`POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}`, `/healthz`).
- `config.py`: Centralized environment configurations and defaults.
- `database.py`: SQLite storage with WAL mode, busy timeouts, and atomic transaction helpers.
- `canonical.py`: Canonical JSON serialization, SHA-256 digests, and secure hex ID generation.
- `planner.py`: AI triage planning using OpenRouter/OpenAI, strict evidence citation validation, and safe prompt construction.
- `state_machine.py`: Deterministic state transitions, 503 retry logic, timeout suppression, approval gating, and effect execution.
- `telemetry.py`: OpenTelemetry OTLP JSON generation, parent-child span hierarchy, and privacy redaction.
- `schemas.py`: Strict schema validation for request payloads and receipts.
- `test_incident_agent.py`: 16 comprehensive automated tests verifying all rubric criteria.
- `requirements.txt`: Python package dependencies.
- `render.yaml`: Infrastructure-as-code deployment configuration for Render.
- `.env.example`: Safe environment variable template.

---

## 2. Local Setup Guide (Windows PowerShell)

Follow these exact steps in Windows PowerShell:

### Step 1: Open PowerShell and Navigate to the Directory
```powershell
cd C:\Users\Admin\Downloads\observable-incident-agent-starter\observable-incident-agent
```

### Step 2: Create and Activate Virtual Environment
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the template to `.env`:
```powershell
Copy-Item .env.example .env
```
Edit `.env` or set environment variables directly in PowerShell:
```powershell
$env:OPENAI_BASE_URL="https://openrouter.ai/api/v1"
$env:OPENAI_API_KEY="your_actual_openrouter_api_key"
$env:MODEL_NAME="openai/gpt-4o-mini"
$env:DATABASE_PATH="incident_agent.sqlite3"
```
*(Note: For offline unit testing without spending API credits, `test_incident_agent.py` automatically runs with simulated deterministic responses).*

### Step 5: Run the Automated Tests
```powershell
pytest -v test_incident_agent.py
```
Expected output: **16 passed in ~2.5s**.

### Step 6: Start the Local Development Server
```powershell
uvicorn app:app --reload --port 8000
```
- Interactive API Docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/healthz`

---

## 3. Deploying to Render (Public HTTPS)

Render provides the public HTTPS base URL required by the assignment grader.

### Step 1: Create a GitHub Repository
1. Initialize git and commit the source files:
   ```powershell
   git init
   git add .
   git commit -m "Complete observable incident triage agent"
   ```
2. Create a new private or public GitHub repository (e.g. `observable-incident-agent`).
3. Push your code:
   ```powershell
   git remote add origin https://github.com/<your-username>/observable-incident-agent.git
   git branch -M main
   git push -u origin main
   ```

### Step 2: Create Web Service on Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub repository.
4. Set the following settings:
   - **Name**: `observable-incident-agent`
   - **Language**: `Python`
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`

### Step 3: Set Environment Variables on Render
Under **Environment Variables**, add:
- `OPENAI_BASE_URL`: `https://openrouter.ai/api/v1`
- `OPENAI_API_KEY`: `<your_openrouter_or_openai_api_key>`
- `MODEL_NAME`: `openai/gpt-4o-mini`
- `DATABASE_PATH`: `incident_agent.sqlite3`

### Step 4: Verify Deployment
Once deployed, verify the public HTTPS URL:
```bash
curl https://<your-service>.onrender.com/healthz
```
Expected response:
```json
{"status": "ok"}
```

---

## 4. API Endpoints Reference

### 1. `POST /v2/incidents`
Submits an incident case, runs AI triage diagnosis, and generates initial diagnostic dispatches.

**Request:**
```http
POST /v2/incidents HTTP/1.1
Content-Type: application/json
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01

{
  "profile": "ga5-incident-agent/v2",
  "runId": "run_prod_001",
  "incident": {
    "incidentId": "inc_alpha_101",
    "title": "Checkout DB pool exhausted",
    "service": "checkout-service",
    "severity": "SEV-1",
    "transcript": "500 errors spike [EV-101]. Connection pool saturated [EV-102].",
    "allowedRootCauses": ["database_connection_exhaustion", "bad_deployment"]
  },
  "toolCatalog": [
    {
      "name": "check_db_pool",
      "description": "Inspect connection pool",
      "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
    },
    {
      "name": "rollback_deployment",
      "description": "Rollback deployment",
      "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
    }
  ],
  "policy": {
    "maximumDiagnostics": 2,
    "effectTools": ["rollback_deployment"],
    "approvalRequiredFor": ["rollback_deployment"],
    "doNotExport": ["apiKey", "dbPassword"]
  },
  "agentName": "incident-triage-agent",
  "publicMarker": "public_marker_xyz",
  "sensitive": {
    "apiKey": "SECRET_SHOULD_NEVER_BE_EXPOSED"
  }
}
```

**Response (200 OK):**
```json
{
  "runId": "run_prod_001",
  "status": "waiting",
  "diagnosis": {
    "rootCause": "database_connection_exhaustion",
    "evidence": ["EV-101", "EV-102"]
  },
  "dispatches": [
    {
      "actionId": "act_8a12bc90ef345678",
      "callId": "call_1234abcd5678efgh",
      "phase": "diagnostic",
      "toolName": "check_db_pool",
      "arguments": {"service": "checkout-service"},
      "evidence": ["EV-101"],
      "attempt": 1,
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-a1b2c3d4e5f60718-01"
    }
  ],
  "approvals": [],
  "actionLog": [...],
  "receiptLog": [],
  "suppressed": [],
  "otlp": {
    "resourceSpans": [...]
  }
}
```

---

### 2. `POST /v2/incidents/{runId}/receipts`
Submits diagnostic results or approvals.

**Diagnostic Outcome Example:**
```http
POST /v2/incidents/run_prod_001/receipts HTTP/1.1
Content-Type: application/json

{
  "receiptId": "rec_outcome_001",
  "outcomes": [
    {
      "actionId": "act_8a12bc90ef345678",
      "callId": "call_1234abcd5678efgh",
      "attempt": 1,
      "status": 200,
      "resultClass": "success",
      "nonce": "n_abc123"
    }
  ]
}
```

**Approval Example (for destructive actions like `rollback_deployment`):**
```http
POST /v2/incidents/run_prod_001/receipts HTTP/1.1
Content-Type: application/json

{
  "receiptId": "rec_approval_001",
  "approvals": [
    {
      "actionId": "act_eff_9921bc45",
      "digest": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
      "approved": true
    }
  ]
}
```

---

### 3. `GET /v2/incidents/{runId}`
Fetches current state, dispatches, approval requests, logs, and OTLP traces.

**Response:**
```json
{
  "runId": "run_prod_001",
  "status": "waiting_approval",
  "diagnosis": {
    "rootCause": "database_connection_exhaustion",
    "evidence": ["EV-101", "EV-102"]
  },
  "dispatches": [],
  "approvals": [
    {
      "actionId": "act_eff_9921bc45",
      "toolName": "rollback_deployment",
      "arguments": {"service": "checkout-service", "rootCause": "database_connection_exhaustion"},
      "phase": "effect",
      "requiresApproval": true,
      "digest": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    }
  ],
  "actionLog": [...],
  "receiptLog": [...],
  "suppressed": [],
  "otlp": {...}
}
```

---

## 5. Important: Grader Checks & Rate Limit Policy

> [!WARNING]
> The assignment portal allows **10 checks per 24 hours**, with the final check reserved for **Save**.
> Only the **latest Save counts** toward your final grade.
> **DO NOT spend grader checks until all 16 local tests pass!**

Submission URL format:
Provide the public HTTPS base URL only (no trailing path, parameters, or fragments):
```
https://<your-render-service-name>.onrender.com
```

---

## 6. Assignment Requirements & Test Verification Matrix

| # | Requirement | Implementation Module | Verified By Automated Test |
|---|---|---|---|
| 1 | FastAPI + Python 3.11+ | `app.py`, `config.py` | `test_health_endpoints` |
| 2 | Endpoints `/v2/incidents`, `/v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}` | `app.py` | `test_valid_incident_creation_and_privacy`, `test_get_incident_state` |
| 3 | AI diagnosis (1 root cause, 2-4 evidence IDs, 1-3 diagnostics) | `planner.py` | `test_valid_incident_creation_and_privacy`, `test_plan_validation_rules` |
| 4 | Evidence citation verification (must exist in transcript) | `planner.py:validate_plan` | `test_plan_validation_rules` |
| 5 | Tool restriction (diagnostics only, never effect tools prematurely) | `planner.py` | `test_plan_validation_rules` |
| 6 | Destructive action approval (`rollback_deployment`, `disable_feature`) | `state_machine.py` | `test_approval_required_destructive_action` |
| 7 | Non-destructive effect direct dispatch | `state_machine.py` | `test_non_destructive_effect_direct_dispatch` |
| 8 | 503 exactly-once retry (stable actionId/callId, new CLIENT span) | `state_machine.py` | `test_receipt_503_retry_logic` |
| 9 | Timeout suppression of dependent effects | `state_machine.py` | `test_receipt_timeout_suppression` |
| 10 | SQLite persistence across server restarts | `database.py` | `test_persistence_across_restart` |
| 11 | Exact duplicate request replay (no duplicate AI or dispatch) | `app.py:create_incident` | `test_duplicate_replay_and_conflict_handling` |
| 12 | Conflicting runId and receiptId (HTTP 409 Conflict) | `app.py` | `test_duplicate_replay_and_conflict_handling`, `test_receipt_idempotency_and_conflict` |
| 13 | Strict schema validation (HTTP 400 & 422) | `schemas.py` | `test_invalid_json_and_missing_fields` |
| 14 | Payload size limit (HTTP 413) | `app.py:check_payload_size` | `test_payload_too_large_413` |
| 15 | Privacy: Redacts `sensitive` and `doNotExport` from prompt/trace/response | `planner.py`, `telemetry.py` | `test_valid_incident_creation_and_privacy` |
| 16 | W3C `traceparent` continuation and OTLP trace validity | `telemetry.py` | `test_traceparent_header_continuation` |
| 17 | Unconfigured planner error (HTTP 503) | `planner.py` | `test_unconfigured_planner_raises_503` |
