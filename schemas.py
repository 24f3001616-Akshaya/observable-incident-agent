from typing import Any, Dict
from fastapi import HTTPException
from config import PROFILE
from canonical import valid_id

def validate_incident_request_json(body: Any) -> Dict[str, Any]:
    """Validate POST /v2/incidents request payload against exact assignment schema."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    req_profile = body.get("profile")
    if req_profile != PROFILE:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported profile: '{req_profile}'. Expected '{PROFILE}'"
        )

    run_id = body.get("runId")
    if not valid_id(run_id):
        raise HTTPException(
            status_code=422,
            detail="runId must be a nonempty opaque ID of at least 8 characters"
        )

    for field in ("incident", "toolCatalog", "policy", "agentName", "publicMarker"):
        if field not in body:
            raise HTTPException(status_code=422, detail=f"Missing required field: '{field}'")

    incident = body.get("incident")
    if not isinstance(incident, dict):
        raise HTTPException(status_code=422, detail="Field 'incident' must be an object")

    for inc_field in ("incidentId", "title", "service", "severity", "transcript", "allowedRootCauses"):
        if inc_field not in incident:
            raise HTTPException(status_code=422, detail=f"Missing required incident field: '{inc_field}'")

    if not isinstance(incident.get("allowedRootCauses"), list) or not incident["allowedRootCauses"]:
        raise HTTPException(status_code=422, detail="incident.allowedRootCauses must be a non-empty list of strings")

    tool_catalog = body.get("toolCatalog")
    if not isinstance(tool_catalog, list):
        raise HTTPException(status_code=422, detail="Field 'toolCatalog' must be an array")

    policy = body.get("policy")
    if not isinstance(policy, dict):
        raise HTTPException(status_code=422, detail="Field 'policy' must be an object")

    return body

def validate_receipt_request_json(body: Any) -> Dict[str, Any]:
    """Validate POST /v2/incidents/{runId}/receipts request payload."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Receipt body must be a JSON object")

    receipt_id = body.get("receiptId")
    if not valid_id(receipt_id):
        raise HTTPException(
            status_code=422,
            detail="receiptId must be a nonempty opaque ID of at least 8 characters"
        )

    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])

    if not isinstance(outcomes, list) or not isinstance(approvals, list):
        raise HTTPException(status_code=422, detail="'outcomes' and 'approvals' must be arrays")

    if not outcomes and not approvals:
        raise HTTPException(
            status_code=422,
            detail="Receipt must contain at least one outcome or approval"
        )

    for o in outcomes:
        if not isinstance(o, dict) or not o.get("actionId") or not o.get("callId"):
            raise HTTPException(status_code=422, detail="Each outcome must include valid actionId and callId")

    for a in approvals:
        if not isinstance(a, dict) or not a.get("actionId") or not a.get("digest"):
            raise HTTPException(status_code=422, detail="Each approval must include valid actionId and digest")

    return body
