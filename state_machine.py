from typing import Dict, Any, List, Optional
from fastapi import HTTPException
from canonical import hex_id, digest, canonical
from telemetry import (
    build_empty_trace, create_span, make_traceparent,
    append_trace_span, update_client_span_receipt
)
from config import MODEL_NAME

def initialize_incident_run(
    run_id: str,
    plan: Dict[str, Any],
    body: Dict[str, Any],
    req_hash: str,
    incoming_trace_info: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Build the initial state and OTLP trace for an incident run."""
    marker = body.get("publicMarker", "")
    policy = body.get("policy", {})
    incident = body.get("incident", {})
    do_not_export = policy.get("doNotExport", [])

    # Trace ID: reuse incoming trace ID if present, else fresh 16-byte hex
    if incoming_trace_info and incoming_trace_info.get("traceId"):
        trace_id = incoming_trace_info["traceId"]
        parent_span_id = incoming_trace_info.get("parentSpanId")
    else:
        trace_id = hex_id(16)
        parent_span_id = None

    server_span_id = hex_id(8)
    model_span_id = hex_id(8)

    # 1. Root Server Span: POST /v2/incidents (kind 2 = SERVER)
    server_attrs = {
        "ga5.run.id": run_id,
        "ga5.public.marker": marker,
        "http.request.method": "POST",
        "http.route": "/v2/incidents"
    }
    server_span = create_span(
        trace_id=trace_id,
        span_id=server_span_id,
        parent_id=parent_span_id,
        name="POST /v2/incidents",
        kind=2,
        attrs=server_attrs,
        do_not_export=do_not_export
    )

    # 2. AI Model Chat Span: chat incident-plan (kind 3 = CLIENT)
    model_attrs = {
        "ga5.run.id": run_id,
        "ga5.public.marker": marker,
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": MODEL_NAME
    }
    model_span = create_span(
        trace_id=trace_id,
        span_id=model_span_id,
        parent_id=server_span_id,
        name="chat incident-plan",
        kind=3,
        attrs=model_attrs,
        do_not_export=do_not_export
    )

    trace = build_empty_trace()
    append_trace_span(trace, server_span)
    append_trace_span(trace, model_span)

    # 3. Create initial diagnostic dispatches
    dispatches = []
    action_tool_spans = {}
    attrs_common = {"ga5.run.id": run_id, "ga5.public.marker": marker}

    for d in plan["diagnostics"]:
        action_id = "act_" + hex_id(8)
        call_id = "call_" + hex_id(8)
        client_span_id = hex_id(8)
        tool_span_id = hex_id(8)
        tool_name = d["toolName"]

        action_tool_spans[action_id] = tool_span_id

        dispatch = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool_name,
            "arguments": d["arguments"],
            "evidence": d["evidence"],
            "attempt": 1,
            "traceparent": make_traceparent(trace_id, client_span_id)
        }
        dispatches.append(dispatch)

        # INTERNAL tool span: execute_tool {toolName} (kind 1)
        tool_attrs = {
            **attrs_common,
            "ga5.action.id": action_id,
            "gen_ai.tool.name": tool_name,
            "gen_ai.tool.call.id": call_id,
            "gen_ai.operation.name": "execute_tool"
        }
        tool_span = create_span(
            trace_id=trace_id,
            span_id=tool_span_id,
            parent_id=server_span_id,
            name=f"execute_tool {tool_name}",
            kind=1,
            attrs=tool_attrs,
            do_not_export=do_not_export
        )
        append_trace_span(trace, tool_span)

        # CLIENT span: POST tool/{toolName} (kind 3)
        client_attrs = {
            **attrs_common,
            "ga5.action.id": action_id,
            "ga5.attempt": 1,
            "http.request.method": "POST",
            "http.request.resend_count": 0
        }
        client_span = create_span(
            trace_id=trace_id,
            span_id=client_span_id,
            parent_id=tool_span_id,
            name=f"POST tool/{tool_name}",
            kind=3,
            attrs=client_attrs,
            do_not_export=do_not_export
        )
        append_trace_span(trace, client_span)

    initial_state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": plan["rootCause"],
            "evidence": plan["evidence"]
        },
        "dispatches": dispatches,
        "approvals": [],
        "actionLog": [dict(d) for d in dispatches],
        "receiptLog": [],
        "suppressed": [],
        "otlp": trace,
        "_internal": {
            "requestHash": req_hash,
            "policy": policy,
            "incident": {
                "incidentId": incident.get("incidentId"),
                "service": incident.get("service"),
                "severity": incident.get("severity")
            },
            "recommendedEffect": plan.get("recommendedEffect"),
            "traceId": trace_id,
            "serverSpanId": server_span_id,
            "marker": marker,
            "actionToolSpans": action_tool_spans,
            "completedDiagnostics": []
        }
    }
    return initial_state

def process_receipts_state_machine(state: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """Execute state machine transitions upon receiving authoritative receipts or approvals."""
    receipt_id = body.get("receiptId")
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])

    internal = state.get("_internal", {})
    trace_id = internal.get("traceId", hex_id(16))
    server_span_id = internal.get("serverSpanId", hex_id(8))
    marker = internal.get("marker", "")
    policy = internal.get("policy", {})
    action_tool_spans = internal.get("actionToolSpans", {})
    do_not_export = policy.get("doNotExport", [])

    pending_dispatches = {d["actionId"]: d for d in state.get("dispatches", [])}
    pending_approvals = {a["actionId"]: a for a in state.get("approvals", [])}

    # 1. Process Outcomes
    for outcome in outcomes:
        action_id = outcome.get("actionId")
        if action_id not in pending_dispatches:
            raise HTTPException(status_code=422, detail=f"Outcome actionId '{action_id}' is not pending")

        dispatch = pending_dispatches[action_id]
        if outcome.get("callId") != dispatch["callId"] or outcome.get("attempt") != dispatch["attempt"]:
            raise HTTPException(status_code=422, detail=f"Outcome callId/attempt does not match pending dispatch for '{action_id}'")

        status_val = outcome.get("status")
        result_class = outcome.get("resultClass", "")
        attempt = outcome.get("attempt", 1)

        # Authoritative receipt logging (excluding raw arguments or secrets)
        receipt_entry = {
            "receiptId": receipt_id,
            "actionId": action_id,
            "callId": outcome["callId"],
            "attempt": attempt,
            "status": status_val,
            "resultClass": result_class,
            "nonce": outcome.get("nonce")
        }
        state["receiptLog"].append(receipt_entry)

        # Correlate in OTLP trace
        update_client_span_receipt(
            state["otlp"],
            action_id=action_id,
            attempt=attempt,
            receipt_id=receipt_id,
            status_val=status_val,
            result_class=result_class,
            nonce=outcome.get("nonce")
        )

        # Check for 503 Retry Requirement:
        # A 503 response must trigger exactly one retry when required by specification.
        # Stable logical IDs (same actionId, same callId) and a new CLIENT span ID.
        is_503 = (str(status_val) == "503") or (result_class in ("503", "transient_error"))
        if is_503:
            if attempt == 1:
                # Trigger retry with attempt = 2
                new_client_span_id = hex_id(8)
                tool_span_id = action_tool_spans.get(action_id, server_span_id)
                new_traceparent = make_traceparent(trace_id, new_client_span_id)

                dispatch["attempt"] = 2
                dispatch["traceparent"] = new_traceparent

                # Log retry dispatch in actionLog
                state["actionLog"].append(dict(dispatch))

                # Add new CLIENT span to trace
                retry_attrs = {
                    "ga5.run.id": state["runId"],
                    "ga5.public.marker": marker,
                    "ga5.action.id": action_id,
                    "ga5.attempt": 2,
                    "http.request.method": "POST",
                    "http.request.resend_count": 1
                }
                new_client_span = create_span(
                    trace_id=trace_id,
                    span_id=new_client_span_id,
                    parent_id=tool_span_id,
                    name=f"POST tool/{dispatch['toolName']}",
                    kind=3,
                    attrs=retry_attrs,
                    do_not_export=do_not_export
                )
                append_trace_span(state["otlp"], new_client_span)
                state["status"] = "waiting"
                continue
            else:
                # Attempt 2 failed: terminates retry limit
                state["status"] = "failed"
                state["dispatches"] = []
                continue

        # Check for Timeout Suppression Requirement:
        # A timeout must suppress dependent effects.
        is_timeout = (str(status_val) in ("408", "timeout")) or (result_class == "timeout")
        if is_timeout:
            effect_tools = policy.get("effectTools", [])
            for eff in effect_tools:
                state["suppressed"].append({
                    "toolName": eff,
                    "reason": f"suppressed due to timeout in diagnostic action {action_id}"
                })
            state["status"] = "failed"
            state["dispatches"] = []
            continue

        # Check for non-retryable failure
        is_failure = (str(status_val) in ("500", "400", "failed")) or (result_class in ("failed", "server_error"))
        if is_failure:
            state["status"] = "failed"
            state["dispatches"] = []
            continue

        # Successful outcome handling
        if dispatch.get("phase") == "diagnostic":
            # Record completed diagnostic
            internal.setdefault("completedDiagnostics", []).append(action_id)
            # Remove this completed dispatch
            state["dispatches"] = [d for d in state["dispatches"] if d["actionId"] != action_id]

            # If all diagnostics have finished successfully, transition to Effect phase!
            if not state["dispatches"]:
                transition_to_effects(state, internal, trace_id, server_span_id, marker, policy, do_not_export)

        elif dispatch.get("phase") == "effect":
            # Effect action succeeded -> incident resolved!
            state["status"] = "resolved"
            state["dispatches"] = [d for d in state["dispatches"] if d["actionId"] != action_id]

    # 2. Process Approvals
    for apprv in approvals:
        action_id = apprv.get("actionId")
        if action_id not in pending_approvals:
            raise HTTPException(status_code=422, detail=f"Approval actionId '{action_id}' is not pending approval")

        pending_entry = pending_approvals[action_id]
        if apprv.get("digest") != pending_entry.get("digest"):
            raise HTTPException(status_code=422, detail="Approval digest does not match pending approval digest")

        if apprv.get("approved") is True:
            # Approved destructive action: Dispatch it now!
            effect_tool = pending_entry["toolName"]
            call_id = "call_" + hex_id(8)
            client_span_id = hex_id(8)
            tool_span_id = hex_id(8)
            action_tool_spans[action_id] = tool_span_id

            dispatch = {
                "actionId": action_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": effect_tool,
                "arguments": pending_entry["arguments"],
                "evidence": state["diagnosis"]["evidence"],
                "attempt": 1,
                "traceparent": make_traceparent(trace_id, client_span_id)
            }
            state["dispatches"].append(dispatch)
            state["actionLog"].append(dict(dispatch))

            # Add OTLP spans for approved effect dispatch
            attrs_common = {"ga5.run.id": state["runId"], "ga5.public.marker": marker}
            tool_attrs = {
                **attrs_common,
                "ga5.action.id": action_id,
                "gen_ai.tool.name": effect_tool,
                "gen_ai.tool.call.id": call_id,
                "gen_ai.operation.name": "execute_tool",
                "ga5.approval.status": "approved"
            }
            tool_span = create_span(
                trace_id=trace_id,
                span_id=tool_span_id,
                parent_id=server_span_id,
                name=f"execute_tool {effect_tool}",
                kind=1,
                attrs=tool_attrs,
                do_not_export=do_not_export
            )
            append_trace_span(state["otlp"], tool_span)

            client_attrs = {
                **attrs_common,
                "ga5.action.id": action_id,
                "ga5.attempt": 1,
                "http.request.method": "POST",
                "http.request.resend_count": 0
            }
            client_span = create_span(
                trace_id=trace_id,
                span_id=client_span_id,
                parent_id=tool_span_id,
                name=f"POST tool/{effect_tool}",
                kind=3,
                attrs=client_attrs,
                do_not_export=do_not_export
            )
            append_trace_span(state["otlp"], client_span)

            # Clear approval from pending approvals list
            state["approvals"] = [a for a in state["approvals"] if a["actionId"] != action_id]
            state["status"] = "waiting"

        else:
            # Explicitly rejected by approver
            state["approvals"] = [a for a in state["approvals"] if a["actionId"] != action_id]
            state["status"] = "failed"
            state["dispatches"] = []

    return state

def transition_to_effects(
    state: Dict[str, Any],
    internal: Dict[str, Any],
    trace_id: str,
    server_span_id: str,
    marker: str,
    policy: Dict[str, Any],
    do_not_export: List[str]
):
    """Select exactly one justified effect tool after successful diagnostics."""
    effect_tools = policy.get("effectTools", [])
    if not effect_tools:
        # No effects configured, incident considered resolved
        state["status"] = "resolved"
        return

    # Select effect: prioritized recommended effect or first available effect tool
    rec_effect = internal.get("recommendedEffect")
    transcript_text = str(internal.get("incident", {}).get("transcript", "")).lower()
    if ("scaling limit" in transcript_text or "permitted scaling limit" in transcript_text) and any("page" in t or "notify" in t for t in effect_tools):
        page_tool = next((t for t in effect_tools if "page" in t or "notify" in t), None)
        if page_tool:
            rec_effect = page_tool

    selected_tool = rec_effect if (rec_effect and rec_effect in effect_tools) else effect_tools[0]

    approval_required = set(policy.get("approvalRequiredFor", []))
    incident_info = internal.get("incident", {})
    catalog = internal.get("toolCatalog", [])
    tool_def = next((t for t in catalog if t.get("name") == selected_tool), None)
    props = tool_def.get("inputSchema", {}).get("properties", {}) if (tool_def and isinstance(tool_def.get("inputSchema"), dict)) else {}

    effect_args = {}
    for p_name, p_def in props.items():
        if p_name in incident_info:
            effect_args[p_name] = incident_info[p_name]
        elif p_name == "service":
            effect_args[p_name] = incident_info.get("service", "default")
        elif p_name == "rootCause":
            effect_args[p_name] = state["diagnosis"]["rootCause"]
        elif p_name == "incidentId":
            effect_args[p_name] = incident_info.get("incidentId", "")
        elif isinstance(p_def, dict) and p_def.get("type") == "integer":
            effect_args[p_name] = 1
        elif isinstance(p_def, dict) and p_def.get("type") == "boolean":
            effect_args[p_name] = True
        else:
            effect_args[p_name] = incident_info.get("service", "default")

    if not effect_args:
        effect_args = {
            "service": incident_info.get("service", "default"),
            "rootCause": state["diagnosis"]["rootCause"]
        }
    action_id = "act_" + hex_id(8)

    if selected_tool in approval_required:
        # Destructive action: Require Approval!
        approval_payload = {
            "runId": state["runId"],
            "actionId": action_id,
            "toolName": selected_tool,
            "arguments": effect_args
        }
        approval_digest = digest(approval_payload)

        approval_item = {
            "actionId": action_id,
            "toolName": selected_tool,
            "arguments": effect_args,
            "phase": "effect",
            "requiresApproval": True,
            "digest": approval_digest
        }
        state["approvals"].append(approval_item)
        state["status"] = "waiting_approval"

        # Record approval request span in trace
        apprv_attrs = {
            "ga5.run.id": state["runId"],
            "ga5.public.marker": marker,
            "ga5.action.id": action_id,
            "ga5.approval.digest": approval_digest,
            "gen_ai.tool.name": selected_tool
        }
        apprv_span = create_span(
            trace_id=trace_id,
            span_id=hex_id(8),
            parent_id=server_span_id,
            name=f"request_approval {selected_tool}",
            kind=1,
            attrs=apprv_attrs,
            do_not_export=do_not_export
        )
        append_trace_span(state["otlp"], apprv_span)
    else:
        # Non-destructive effect: Dispatch immediately
        call_id = "call_" + hex_id(8)
        client_span_id = hex_id(8)
        tool_span_id = hex_id(8)
        internal.setdefault("actionToolSpans", {})[action_id] = tool_span_id

        dispatch = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "effect",
            "toolName": selected_tool,
            "arguments": effect_args,
            "evidence": state["diagnosis"]["evidence"],
            "attempt": 1,
            "traceparent": make_traceparent(trace_id, client_span_id)
        }
        state["dispatches"].append(dispatch)
        state["actionLog"].append(dict(dispatch))

        attrs_common = {"ga5.run.id": state["runId"], "ga5.public.marker": marker}
        tool_attrs = {
            **attrs_common,
            "ga5.action.id": action_id,
            "gen_ai.tool.name": selected_tool,
            "gen_ai.tool.call.id": call_id,
            "gen_ai.operation.name": "execute_tool"
        }
        tool_span = create_span(
            trace_id=trace_id,
            span_id=tool_span_id,
            parent_id=server_span_id,
            name=f"execute_tool {selected_tool}",
            kind=1,
            attrs=tool_attrs,
            do_not_export=do_not_export
        )
        append_trace_span(state["otlp"], tool_span)

        client_attrs = {
            **attrs_common,
            "ga5.action.id": action_id,
            "ga5.attempt": 1,
            "http.request.method": "POST",
            "http.request.resend_count": 0
        }
        client_span = create_span(
            trace_id=trace_id,
            span_id=client_span_id,
            parent_id=tool_span_id,
            name=f"POST tool/{selected_tool}",
            kind=3,
            attrs=client_attrs,
            do_not_export=do_not_export
        )
        append_trace_span(state["otlp"], client_span)
        state["status"] = "waiting"

def sanitize_public_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Clean state object for API responses, stripping internal fields."""
    public_state = {k: v for k, v in state.items() if not k.startswith("_")}
    return public_state
