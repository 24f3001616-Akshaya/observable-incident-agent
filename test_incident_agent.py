import os
import json
import pytest
import tempfile
import httpx
from fastapi.testclient import TestClient

# Set test environment flags
os.environ["MOCK_PLANNER"] = "1"
os.environ["OPENAI_API_KEY"] = "mock-key-for-tests"
os.environ["MODEL_NAME"] = "test-model"

import database
import config
from app import app
from canonical import canonical, digest

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Ensure each test runs with a fresh, isolated SQLite database."""
    test_db = str(tmp_path / "test_incident.sqlite3")
    config.DB_PATH = test_db
    database.DB_PATH = test_db
    database.init_db(test_db)
    yield test_db

@pytest.fixture
def sample_payload():
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": "run_test_001",
        "incident": {
            "incidentId": "inc_alpha_101",
            "title": "Elevated checkout errors on checkout-service",
            "service": "checkout-service",
            "severity": "SEV-1",
            "transcript": "Customer reported 500 error [EV-101]. Database connection pool exhausted [EV-102]. Replica lag spike observed [EV-103].",
            "allowedRootCauses": [
                "database_connection_exhaustion",
                "bad_deployment_v2",
                "third_party_timeout"
            ]
        },
        "toolCatalog": [
            {
                "name": "check_db_pool",
                "description": "Inspect database connection pool metrics",
                "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
            },
            {
                "name": "check_replica_lag",
                "description": "Inspect database replica lag",
                "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
            },
            {
                "name": "rollback_deployment",
                "description": "Rollback recent deployment",
                "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
            },
            {
                "name": "restart_service",
                "description": "Restart service container",
                "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
            }
        ],
        "policy": {
            "maximumDiagnostics": 2,
            "effectTools": ["rollback_deployment", "restart_service"],
            "approvalRequiredFor": ["rollback_deployment"],
            "doNotExport": ["apiKey", "dbPassword", "customerSecret"]
        },
        "agentName": "incident-triage-agent",
        "publicMarker": "public_marker_alpha",
        "sensitive": {
            "customerSecret": "SUPER_SECRET_TOKEN_DO_NOT_EXPOSE",
            "dbPassword": "super_secret_db_password"
        }
    }

def test_health_endpoints():
    """Verify / and /healthz endpoints."""
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["service"] == "observable-incident-agent"
        assert data["profile"] == "ga5-incident-agent/v2"
        assert data["status"] == "ready"

        r_health = client.get("/healthz")
        assert r_health.status_code == 200
        assert r_health.json() == {"status": "ok"}

def test_valid_incident_creation_and_privacy(sample_payload):
    """Verify valid incident request, diagnosis, dispatches, OTLP trace, and privacy."""
    with TestClient(app) as client:
        response = client.post("/v2/incidents", json=sample_payload)
        assert response.status_code == 200
        data = response.json()

        assert data["runId"] == "run_test_001"
        assert data["status"] == "waiting"
        assert "diagnosis" in data
        assert data["diagnosis"]["rootCause"] in sample_payload["incident"]["allowedRootCauses"]
        assert 2 <= len(data["diagnosis"]["evidence"]) <= 4

        # Dispatches must be diagnostic tools only
        assert len(data["dispatches"]) > 0
        effect_tools = set(sample_payload["policy"]["effectTools"])
        for d in data["dispatches"]:
            assert d["phase"] == "diagnostic"
            assert d["toolName"] not in effect_tools
            assert d["attempt"] == 1
            assert "traceparent" in d

        # Trace checks
        assert "otlp" in data
        spans = data["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        assert len(spans) >= 2

        # Privacy checks: Sensitive information must NEVER appear in state or traces
        raw_dump = json.dumps(data)
        assert "SUPER_SECRET_TOKEN_DO_NOT_EXPOSE" not in raw_dump
        assert "super_secret_db_password" not in raw_dump
        assert "_internal" not in data

def test_invalid_json_and_missing_fields(sample_payload):
    """Verify validation: invalid profile, missing runId, missing fields return 400 or 422."""
    with TestClient(app) as client:
        # Invalid JSON
        r = client.post("/v2/incidents", content=b"invalid json{", headers={"Content-Type": "application/json"})
        assert r.status_code == 400

        # Wrong profile
        bad_profile = dict(sample_payload)
        bad_profile["profile"] = "wrong-profile"
        r = client.post("/v2/incidents", json=bad_profile)
        assert r.status_code == 400

        # Invalid runId (too short)
        short_id = dict(sample_payload)
        short_id["runId"] = "short"
        r = client.post("/v2/incidents", json=short_id)
        assert r.status_code == 422

        # Missing required field
        missing_marker = dict(sample_payload)
        del missing_marker["publicMarker"]
        r = client.post("/v2/incidents", json=missing_marker)
        assert r.status_code == 422

def test_duplicate_replay_and_conflict_handling(sample_payload):
    """Verify idempotency: replaying identical runId returns cached result; differing payload returns 409."""
    with TestClient(app) as client:
        r1 = client.post("/v2/incidents", json=sample_payload)
        assert r1.status_code == 200
        data1 = r1.json()

        # Exact replay: same runId, same payload -> returns 200 with identical cached state
        r2 = client.post("/v2/incidents", json=sample_payload)
        assert r2.status_code == 200
        data2 = r2.json()
        assert data1 == data2

        # Conflict: same runId, different content -> HTTP 409
        conflicting = dict(sample_payload)
        conflicting["publicMarker"] = "different_marker"
        r3 = client.post("/v2/incidents", json=conflicting)
        assert r3.status_code == 409
        assert "runId already exists with different content" in r3.json()["detail"]

def test_get_incident_state(sample_payload):
    """Verify GET /v2/incidents/{runId} returns 404 for unknown, 200 for existing."""
    with TestClient(app) as client:
        r404 = client.get("/v2/incidents/run_nonexistent")
        assert r404.status_code == 404

        client.post("/v2/incidents", json=sample_payload)
        r_ok = client.get(f"/v2/incidents/{sample_payload['runId']}")
        assert r_ok.status_code == 200
        assert r_ok.json()["runId"] == sample_payload["runId"]

def test_receipt_503_retry_logic(sample_payload):
    """Verify 503 triggers exactly one retry with stable logical IDs and new client span."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        dispatch = init_res["dispatches"][0]
        action_id = dispatch["actionId"]
        call_id = dispatch["callId"]
        original_traceparent = dispatch["traceparent"]

        # First receipt with 503 status
        receipt_503 = {
            "receiptId": "rec_transient_001",
            "outcomes": [
                {
                    "actionId": action_id,
                    "callId": call_id,
                    "attempt": 1,
                    "status": 503,
                    "resultClass": "transient_error",
                    "nonce": "n_503_test"
                }
            ]
        }
        res_503 = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=receipt_503)
        assert res_503.status_code == 200
        data_retry = res_503.json()

        # State should still be waiting
        assert data_retry["status"] == "waiting"
        # Must contain retried dispatch with attempt = 2
        retry_dispatch = next(d for d in data_retry["dispatches"] if d["actionId"] == action_id)
        assert retry_dispatch["attempt"] == 2
        assert retry_dispatch["callId"] == call_id  # Stable callId
        assert retry_dispatch["actionId"] == call_id or retry_dispatch["actionId"] == action_id  # Stable actionId
        assert retry_dispatch["traceparent"] != original_traceparent  # New CLIENT span ID!

        # Receipt logged in receiptLog
        assert any(r["receiptId"] == "rec_transient_001" for r in data_retry["receiptLog"])

        # Second 503 outcome must exceed retry limit and fail run
        receipt_503_fail = {
            "receiptId": "rec_transient_002",
            "outcomes": [
                {
                    "actionId": action_id,
                    "callId": call_id,
                    "attempt": 2,
                    "status": 503,
                    "resultClass": "transient_error"
                }
            ]
        }
        res_fail = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=receipt_503_fail)
        assert res_fail.status_code == 200
        assert res_fail.json()["status"] == "failed"
        assert len(res_fail.json()["dispatches"]) == 0

def test_receipt_timeout_suppression(sample_payload):
    """Verify timeout outcome suppresses dependent effects."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        dispatch = init_res["dispatches"][0]

        receipt_timeout = {
            "receiptId": "rec_timeout_001",
            "outcomes": [
                {
                    "actionId": dispatch["actionId"],
                    "callId": dispatch["callId"],
                    "attempt": 1,
                    "status": 408,
                    "resultClass": "timeout"
                }
            ]
        }
        res = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=receipt_timeout)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "failed"
        assert len(data["suppressed"]) > 0
        suppressed_tools = [s["toolName"] for s in data["suppressed"]]
        assert "rollback_deployment" in suppressed_tools or "restart_service" in suppressed_tools

def test_approval_required_destructive_action(sample_payload):
    """Verify successful diagnostics leading to an approval-gated destructive effect and its execution."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        dispatches = init_res["dispatches"]

        # Complete all diagnostics with 200 success
        outcomes = [
            {
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "resultClass": "success"
            }
            for d in dispatches
        ]
        res_diag = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={"receiptId": "rec_diag_ok_001", "outcomes": outcomes}
        )
        assert res_diag.status_code == 200
        state_diag = res_diag.json()

        # Destructive tool 'rollback_deployment' requires approval!
        assert state_diag["status"] == "waiting_approval"
        assert len(state_diag["approvals"]) == 1
        pending_apprv = state_diag["approvals"][0]
        assert pending_apprv["toolName"] == "rollback_deployment"
        assert pending_apprv["requiresApproval"] is True
        assert "digest" in pending_apprv

        # Reject bad digest approval -> 422
        bad_approval = {
            "receiptId": "rec_apprv_bad_001",
            "approvals": [
                {
                    "actionId": pending_apprv["actionId"],
                    "digest": "invalid_digest_hex",
                    "approved": True
                }
            ]
        }
        res_bad = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=bad_approval)
        assert res_bad.status_code == 422

        # Send valid approval
        good_approval = {
            "receiptId": "rec_apprv_ok_001",
            "approvals": [
                {
                    "actionId": pending_apprv["actionId"],
                    "digest": pending_apprv["digest"],
                    "approved": True
                }
            ]
        }
        res_approved = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=good_approval)
        assert res_approved.status_code == 200
        state_approved = res_approved.json()

        # After approval, destructive effect is dispatched!
        assert state_approved["status"] == "waiting"
        assert len(state_approved["dispatches"]) == 1
        effect_dispatch = state_approved["dispatches"][0]
        assert effect_dispatch["phase"] == "effect"
        assert effect_dispatch["toolName"] == "rollback_deployment"

        # Now complete effect dispatch with 200 -> Incident resolved!
        res_final = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={
                "receiptId": "rec_effect_ok_001",
                "outcomes": [
                    {
                        "actionId": effect_dispatch["actionId"],
                        "callId": effect_dispatch["callId"],
                        "attempt": 1,
                        "status": 200,
                        "resultClass": "success"
                    }
                ]
            }
        )
        assert res_final.status_code == 200
        assert res_final.json()["status"] == "resolved"

def test_receipt_idempotency_and_conflict(sample_payload):
    """Verify receipt idempotency and conflict (HTTP 409)."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        dispatch = init_res["dispatches"][0]

        receipt_payload = {
            "receiptId": "rec_repeat_001",
            "outcomes": [
                {
                    "actionId": dispatch["actionId"],
                    "callId": dispatch["callId"],
                    "attempt": 1,
                    "status": 200,
                    "resultClass": "success"
                }
            ]
        }
        # First call -> 200
        r1 = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=receipt_payload)
        assert r1.status_code == 200
        res1 = r1.json()

        # Replay identical receipt -> 200 identical
        r2 = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=receipt_payload)
        assert r2.status_code == 200
        assert r2.json() == res1

        # Conflicting receiptId with different body -> 409
        conflicting_receipt = {
            "receiptId": "rec_repeat_001",
            "outcomes": [
                {
                    "actionId": dispatch["actionId"],
                    "callId": dispatch["callId"],
                    "attempt": 1,
                    "status": 500,
                    "resultClass": "server_error"
                }
            ]
        }
        r3 = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=conflicting_receipt)
        assert r3.status_code == 409

def test_traceparent_header_continuation(sample_payload):
    """Verify that incoming W3C traceparent header propagates trace ID and parent span ID."""
    with TestClient(app) as client:
        incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        incoming_span_id = "00f067aa0ba902b7"
        tp_header = f"00-{incoming_trace_id}-{incoming_span_id}-01"

        res = client.post("/v2/incidents", json=sample_payload, headers={"traceparent": tp_header})
        assert res.status_code == 200
        data = res.json()

        trace = data["otlp"]
        spans = trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
        root_server_span = next(s for s in spans if s["name"] == "POST /v2/incidents")

        assert root_server_span["traceId"] == incoming_trace_id
        assert root_server_span.get("parentSpanId") == incoming_span_id

def test_persistence_across_restart(sample_payload, tmp_path):
    """Simulate server restart by closing connection and verifying DB state reload."""
    test_db = str(tmp_path / "restart_test.sqlite3")
    config.DB_PATH = test_db
    database.DB_PATH = test_db
    database.init_db(test_db)

    with TestClient(app) as client:
        r = client.post("/v2/incidents", json=sample_payload)
        assert r.status_code == 200
        run_id = sample_payload["runId"]

    # "Server Restart": Create a brand new client pointing to the same SQLite DB file
    database.init_db(test_db)
    with TestClient(app) as new_client:
        r_get = new_client.get(f"/v2/incidents/{run_id}")
        assert r_get.status_code == 200
        assert r_get.json()["runId"] == run_id
        assert r_get.json()["status"] == "waiting"

def test_unconfigured_planner_raises_503(sample_payload, monkeypatch):
    """Verify 503 is returned if AI planner credentials are not set when live planner is used."""
    monkeypatch.delenv("MOCK_PLANNER", raising=False)
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    import planner
    monkeypatch.setattr(planner, "OPENAI_API_KEY", "")

    with TestClient(app) as client:
        sample_copy = dict(sample_payload)
        sample_copy["runId"] = "run_unconfigured_key"
        res = client.post("/v2/incidents", json=sample_copy)
        assert res.status_code == 503
        assert "AI planner is not configured" in res.json()["detail"]

def test_plan_validation_rules(sample_payload):
    """Verify strict validation of AI planner output against policy and evidence."""
    import planner

    # 1. Unsupported root cause
    bad_plan = {
        "rootCause": "invented_alien_attack",
        "evidence": ["EV-101", "EV-102"],
        "diagnostics": [{"toolName": "check_db_pool", "arguments": {}, "evidence": ["EV-101"]}]
    }
    with pytest.raises(Exception) as exc_info:
        planner.validate_plan(bad_plan, sample_payload)
    assert "unsupported root cause" in str(exc_info.value.detail).lower()

    # 2. Fabricated evidence ID not in transcript
    bad_ev_plan = {
        "rootCause": "database_connection_exhaustion",
        "evidence": ["EV-101", "EV-FAKE-999"],
        "diagnostics": [{"toolName": "check_db_pool", "arguments": {}, "evidence": ["EV-101"]}]
    }
    with pytest.raises(Exception) as exc_info:
        planner.validate_plan(bad_ev_plan, sample_payload)
    assert "not present in transcript" in str(exc_info.value.detail).lower()

    # 3. Diagnostic selection of an effect tool
    bad_tool_plan = {
        "rootCause": "database_connection_exhaustion",
        "evidence": ["EV-101", "EV-102"],
        "diagnostics": [{"toolName": "rollback_deployment", "arguments": {}, "evidence": ["EV-101"]}]
    }
    with pytest.raises(Exception) as exc_info:
        planner.validate_plan(bad_tool_plan, sample_payload)
    assert "effect tool" in str(exc_info.value.detail).lower()

    # 4. Exceeding maximumDiagnostics limit
    too_many_plan = {
        "rootCause": "database_connection_exhaustion",
        "evidence": ["EV-101", "EV-102"],
        "diagnostics": [
            {"toolName": "check_db_pool", "arguments": {}, "evidence": ["EV-101"]},
            {"toolName": "check_replica_lag", "arguments": {}, "evidence": ["EV-102"]},
            {"toolName": "check_db_pool", "arguments": {}, "evidence": ["EV-101"]}
        ]
    }
    with pytest.raises(Exception) as exc_info:
        planner.validate_plan(too_many_plan, sample_payload)
    assert "diagnostic tools" in str(exc_info.value.detail).lower()

def test_approval_rejected_sets_failed(sample_payload):
    """Verify that an explicitly rejected approval transitions incident to failed status."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        dispatches = init_res["dispatches"]

        outcomes = [
            {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 200, "resultClass": "success"}
            for d in dispatches
        ]
        res_diag = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={"receiptId": "rec_diag_ok_reject_flow", "outcomes": outcomes}
        ).json()

        apprv = res_diag["approvals"][0]
        # Reject the approval
        reject_receipt = {
            "receiptId": "rec_reject_001",
            "approvals": [
                {
                    "actionId": apprv["actionId"],
                    "digest": apprv["digest"],
                    "approved": False
                }
            ]
        }
        res_reject = client.post(f"/v2/incidents/{sample_payload['runId']}/receipts", json=reject_receipt)
        assert res_reject.status_code == 200
        data_rej = res_reject.json()
        assert data_rej["status"] == "failed"
        assert len(data_rej["dispatches"]) == 0

def test_payload_too_large_413():
    """Verify that payloads exceeding max size are rejected with HTTP 413."""
    with TestClient(app) as client:
        # Create a 2MB dummy payload
        big_content = "x" * (1024 * 1024 * 2)
        res = client.post(
            "/v2/incidents",
            content=big_content.encode("utf-8"),
            headers={"Content-Length": str(len(big_content)), "Content-Type": "application/json"}
        )
        assert res.status_code == 413

def test_non_destructive_effect_direct_dispatch(sample_payload):
    """Verify that an effect tool not in approvalRequiredFor is dispatched directly without approval gating."""
    # Modify payload so recommended effect does not require approval
    mod_payload = dict(sample_payload)
    mod_payload["runId"] = "run_non_destructive_001"
    mod_payload["policy"] = {
        "maximumDiagnostics": 1,
        "effectTools": ["restart_service"],
        "approvalRequiredFor": ["rollback_deployment"],  # restart_service does NOT require approval
        "doNotExport": []
    }

    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=mod_payload).json()
        dispatch = init_res["dispatches"][0]

        # Complete diagnostic with 200
        res = client.post(
            f"/v2/incidents/{mod_payload['runId']}/receipts",
            json={
                "receiptId": "rec_nondestruct_diag",
                "outcomes": [
                    {
                        "actionId": dispatch["actionId"],
                        "callId": dispatch["callId"],
                        "attempt": 1,
                        "status": 200,
                        "resultClass": "success"
                    }
                ]
            }
        ).json()

        # Non-destructive effect should be dispatched directly!
        assert res["status"] == "waiting"
        assert len(res["approvals"]) == 0
        assert len(res["dispatches"]) == 1
        effect_disp = res["dispatches"][0]
        assert effect_disp["phase"] == "effect"
        assert effect_disp["toolName"] == "restart_service"

def test_grader_category_1_proposal(sample_payload):
    """Category 1: Proposal - supported root cause, required evidence IDs, diagnostic dispatches before effects."""
    with TestClient(app) as client:
        res = client.post("/v2/incidents", json=sample_payload)
        assert res.status_code == 200
        data = res.json()

        # 1. Supported root cause from allowedRootCauses
        assert "diagnosis" in data
        assert data["diagnosis"]["rootCause"] in sample_payload["incident"]["allowedRootCauses"]

        # 2. Exact required evidence IDs (2-4 distinct, matching transcript)
        evidence = data["diagnosis"]["evidence"]
        assert isinstance(evidence, list)
        assert 2 <= len(evidence) <= 4
        assert len(set(evidence)) == len(evidence)
        for e in evidence:
            assert e in sample_payload["incident"]["transcript"]

        # 3. Only permitted diagnostic tools dispatched before effects
        assert len(data["dispatches"]) > 0
        effect_tools = set(sample_payload["policy"]["effectTools"])
        for d in data["dispatches"]:
            assert d["phase"] == "diagnostic"
            assert d["toolName"] not in effect_tools
            assert d["attempt"] == 1
            assert "traceparent" in d
            assert len(d["evidence"]) >= 1
            assert all(e in evidence for e in d["evidence"])

def test_grader_category_2_action_semantics(sample_payload):
    """Category 2: Action Semantics - exact case-derived arguments and real outcome reporting."""
    case_payload = dict(sample_payload)
    case_payload["runId"] = "run_case_semantics_001"
    case_payload["incident"] = dict(sample_payload["incident"])
    case_payload["incident"]["service"] = "payment-service"
    case_payload["incident"]["transcript"] = (
        "Spike observed in us-east-1 on service payment-service after deployment d-99a1 [EV-101]. "
        "Pool limit saturated [EV-102]."
    )
    case_payload["toolCatalog"] = [
        {
            "name": "check_pool",
            "description": "Inspect pool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "region": {"type": "string"},
                    "deploymentId": {"type": "string"}
                }
            }
        }
    ]
    case_payload["policy"]["effectTools"] = []

    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=case_payload).json()
        assert len(init_res["dispatches"]) == 1
        disp = init_res["dispatches"][0]

        # Case-derived arguments verification
        args = disp["arguments"]
        assert args.get("region") == "us-east-1"
        assert args.get("deploymentId") == "d-99a1"
        assert args.get("service") == "payment-service"

        # Report real tool result via receipt
        receipt_payload = {
            "receiptId": "rec_real_result_001",
            "outcomes": [
                {
                    "actionId": disp["actionId"],
                    "callId": disp["callId"],
                    "attempt": 1,
                    "status": 200,
                    "resultClass": "success",
                    "result": {"active_connections": 99, "pool_limit": 100},
                    "nonce": "n_sec_123"
                }
            ]
        }
        res = client.post(f"/v2/incidents/{case_payload['runId']}/receipts", json=receipt_payload).json()
        
        # Real result reported in logs
        assert len(res["receiptLog"]) == 1
        r_log = res["receiptLog"][0]
        assert r_log["receiptId"] == "rec_real_result_001"
        assert r_log["status"] == 200
        assert r_log["resultClass"] == "success"
        assert r_log["nonce"] == "n_sec_123"

        # Real result reported in actionLog
        a_log = next(a for a in res["actionLog"] if a["actionId"] == disp["actionId"])
        assert a_log["status"] == 200
        assert a_log["resultClass"] == "success"
        assert a_log["nonce"] == "n_sec_123"

def test_grader_category_3_trace_topology(sample_payload):
    """Category 3: Trace Topology - continuity, unique span IDs, parent links, span counts, and final join."""
    with TestClient(app) as client:
        tp_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        init_res = client.post("/v2/incidents", json=sample_payload, headers={"traceparent": tp_header}).json()

        # 1. Trace continuity: traceId preserved
        spans_1 = init_res["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        expected_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        for s in spans_1:
            assert s["traceId"] == expected_trace_id

        # 2. Unique span IDs
        span_ids_1 = [s["spanId"] for s in spans_1]
        assert len(span_ids_1) == len(set(span_ids_1))

        # 3. Complete diagnostics to transition through receipt and resolution
        diag_outcomes = [
            {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 200, "resultClass": "success"}
            for d in init_res["dispatches"]
        ]
        res_diag = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={"receiptId": "rec_topo_diag_01", "outcomes": diag_outcomes}
        ).json()

        # Approve destructive action
        apprv = res_diag["approvals"][0]
        res_apprv = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={"receiptId": "rec_topo_apprv_01", "approvals": [{"actionId": apprv["actionId"], "digest": apprv["digest"], "approved": True}]}
        ).json()

        # Complete effect tool
        eff_disp = res_apprv["dispatches"][0]
        res_final = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={"receiptId": "rec_topo_eff_01", "outcomes": [{"actionId": eff_disp["actionId"], "callId": eff_disp["callId"], "attempt": 1, "status": 200, "resultClass": "success"}]}
        ).json()

        assert res_final["status"] == "resolved"

        # Verify final spans
        all_spans = res_final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        all_span_ids = [s["spanId"] for s in all_spans]
        assert len(all_span_ids) == len(set(all_span_ids))

        # Continuity across all spans
        for s in all_spans:
            assert s["traceId"] == expected_trace_id

        # Root server span
        root_span = next(s for s in all_spans if s["name"] == "POST /v2/incidents")
        assert root_span["kind"] == 2
        assert root_span.get("parentSpanId") == "00f067aa0ba902b7"

        # Final join span linking back to root
        join_span = next((s for s in all_spans if s["name"] == "join"), None)
        assert join_span is not None
        assert join_span["parentSpanId"] == root_span["spanId"]
        assert any(link.get("spanId") == root_span["spanId"] for link in join_span.get("links", []))

def test_grader_category_4_correlation(sample_payload):
    """Category 4: Correlation - connect action, call, attempt, approval, and receipt across spans and logs."""
    with TestClient(app) as client:
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        d = init_res["dispatches"][0]

        receipt_id = "rec_corr_test_01"
        nonce = "nonce_corr_xyz"
        res = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={
                "receiptId": receipt_id,
                "outcomes": [
                    {
                        "actionId": d["actionId"],
                        "callId": d["callId"],
                        "attempt": 1,
                        "status": 200,
                        "resultClass": "success",
                        "nonce": nonce
                    }
                ]
            }
        ).json()

        # Check logs
        r_entry = next(r for r in res["receiptLog"] if r["actionId"] == d["actionId"])
        assert r_entry["callId"] == d["callId"]
        assert r_entry["receiptId"] == receipt_id
        assert r_entry["nonce"] == nonce

        # Check spans correlation
        spans = res["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        client_span = next(s for s in spans if s["kind"] == 3 and s["name"] == f"POST tool/{d['toolName']}")
        c_attrs = {a["key"]: a["value"]["stringValue"] for a in client_span["attributes"]}
        assert c_attrs["ga5.action.id"] == d["actionId"]
        assert c_attrs["ga5.call.id"] == d["callId"]
        assert c_attrs["ga5.receipt.id"] == receipt_id
        assert c_attrs["ga5.receipt.status"] == "200"
        assert c_attrs["ga5.receipt.nonce"] == nonce

def test_grader_category_5_lifecycle(sample_payload):
    """Category 5: Lifecycle - retry logic, timeout suppression, approval gating, and completion."""
    with TestClient(app) as client:
        # 1. 503 retry triggers attempt 2 with stable actionId and callId
        init_res = client.post("/v2/incidents", json=sample_payload).json()
        d = init_res["dispatches"][0]
        res_503 = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={
                "receiptId": "rec_life_503_01",
                "outcomes": [{"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 503, "resultClass": "transient_error"}]
            }
        ).json()

        assert res_503["status"] == "waiting"
        retry_d = res_503["dispatches"][0]
        assert retry_d["actionId"] == d["actionId"]
        assert retry_d["callId"] == d["callId"]
        assert retry_d["attempt"] == 2

        # 2. Second 503 fails run
        res_fail = client.post(
            f"/v2/incidents/{sample_payload['runId']}/receipts",
            json={
                "receiptId": "rec_life_503_02",
                "outcomes": [{"actionId": retry_d["actionId"], "callId": retry_d["callId"], "attempt": 2, "status": 503, "resultClass": "transient_error"}]
            }
        ).json()
        assert res_fail["status"] == "failed"
        assert len(res_fail["dispatches"]) == 0

def test_grader_category_6_durability(sample_payload, tmp_path):
    """Category 6: Durability - replay idempotency, conflict rejection, and self-healing DB recovery."""
    with TestClient(app) as client:
        # 1. Replay identical request returns exact stored state
        res1 = client.post("/v2/incidents", json=sample_payload).json()
        res2 = client.post("/v2/incidents", json=sample_payload).json()
        assert res1["runId"] == res2["runId"]
        assert res1["diagnosis"] == res2["diagnosis"]

        # 2. Conflicting runId returns HTTP 409
        conflict_payload = dict(sample_payload)
        conflict_payload["publicMarker"] = "different_marker"
        r_conf = client.post("/v2/incidents", json=conflict_payload)
        assert r_conf.status_code == 409

        # 3. GET /v2/incidents/{runId} returns stored state
        r_get = client.get(f"/v2/incidents/{sample_payload['runId']}")
        assert r_get.status_code == 200
        assert r_get.json()["runId"] == sample_payload["runId"]

        # 4. Self-healing DB recovery from malformed file
        corrupt_file = str(tmp_path / "corrupt_test.sqlite3")
        with open(corrupt_file, "wb") as f:
            f.write(b"NOT_A_VALID_SQLITE_DATABASE_CORRUPT")
        database.init_db(corrupt_file)
        with database.get_db(corrupt_file) as conn:
            cnt = conn.execute("SELECT count(*) as c FROM runs").fetchone()["c"]
            assert cnt == 0


