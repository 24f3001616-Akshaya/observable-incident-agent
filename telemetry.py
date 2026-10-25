import re
from typing import Optional, Dict, Any, List
from canonical import hex_id, now_unix_nano

TRACEPARENT_RE = re.compile(r"^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$")

# Redacted keys for privacy
SENSITIVE_KEY_PATTERNS = {"password", "secret", "token", "apikey", "api_key", "bearer", "authorization", "sensitive"}

def parse_traceparent(tp_header: Optional[str]) -> Optional[Dict[str, str]]:
    """Parse W3C Trace Context traceparent header if valid."""
    if not tp_header or not isinstance(tp_header, str):
        return None
    m = TRACEPARENT_RE.match(tp_header.strip())
    if not m:
        return None
    trace_id, parent_span_id, flags = m.groups()
    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None
    return {"traceId": trace_id.lower(), "parentSpanId": parent_span_id.lower(), "flags": flags.lower()}

def make_traceparent(trace_id: str, span_id: str) -> str:
    """Construct W3C Trace Context traceparent header."""
    return f"00-{trace_id}-{span_id}-01"

def is_sensitive_key(key: str, do_not_export: Optional[List[str]] = None) -> bool:
    """Check if an attribute key matches privacy filter or doNotExport list."""
    k_lower = key.lower()
    if any(pat in k_lower for pat in SENSITIVE_KEY_PATTERNS):
        return True
    if do_not_export:
        for dne in do_not_export:
            if dne and dne.lower() in k_lower:
                return True
    return False

def sanitize_attributes(attrs: Dict[str, Any], do_not_export: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Filter out sensitive keys and format as OTLP attribute list."""
    out = []
    for k, v in (attrs or {}).items():
        if is_sensitive_key(k, do_not_export):
            continue
        out.append({"key": str(k), "value": {"stringValue": str(v)}})
    return out

def create_span(
    trace_id: str,
    span_id: str,
    parent_id: Optional[str],
    name: str,
    kind: int,
    attrs: Optional[Dict[str, Any]] = None,
    links: Optional[List[Dict[str, Any]]] = None,
    status: Optional[Dict[str, Any]] = None,
    do_not_export: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Create an OpenTelemetry compliant span dictionary."""
    t_nano = now_unix_nano()
    s = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": t_nano,
        "endTimeUnixNano": t_nano,
        "attributes": sanitize_attributes(attrs or {}, do_not_export)
    }
    if parent_id:
        s["parentSpanId"] = parent_id
    if links:
        s["links"] = links
    if status is not None:
        s["status"] = status
    return s

def build_empty_trace() -> Dict[str, Any]:
    """Build root OTLP ResourceSpans envelope."""
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "observable-incident-agent"}},
                        {"key": "service.version", "value": {"stringValue": "0.1.0"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "ga5-incident-agent", "version": "v2"},
                        "spans": []
                    }
                ]
            }
        ]
    }

def get_trace_spans(trace: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for rs in trace.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            out.extend(ss.get("spans", []))
    return out

def set_trace_spans(trace: Dict[str, Any], spans: List[Dict[str, Any]]):
    if not trace.get("resourceSpans"):
        trace["resourceSpans"] = [{"scopeSpans": [{"spans": []}]}]
    if not trace["resourceSpans"][0].get("scopeSpans"):
        trace["resourceSpans"][0]["scopeSpans"] = [{"spans": []}]
    trace["resourceSpans"][0]["scopeSpans"][0]["spans"] = spans

def append_trace_span(trace: Dict[str, Any], span: Dict[str, Any]):
    spans = get_trace_spans(trace)
    spans.append(span)
    set_trace_spans(trace, spans)

def find_span_by_attr(trace: Dict[str, Any], attr_key: str, attr_val: str) -> Optional[Dict[str, Any]]:
    for s in get_trace_spans(trace):
        for a in s.get("attributes", []):
            if a.get("key") == attr_key and a.get("value", {}).get("stringValue") == str(attr_val):
                return s
    return None

def update_client_span_receipt(
    trace: Dict[str, Any],
    action_id: str,
    attempt: int,
    receipt_id: str,
    status_val: Any,
    result_class: Optional[str] = None,
    nonce: Optional[str] = None
):
    """Correlate receipt outcome with the corresponding client span in the trace."""
    target_span = None
    for s in get_trace_spans(trace):
        attrs = {a.get("key"): a.get("value", {}).get("stringValue") for a in s.get("attributes", [])}
        if attrs.get("ga5.action.id") == action_id and str(attrs.get("ga5.attempt")) == str(attempt) and s.get("kind") == 3:
            target_span = s
            break
    
    if not target_span:
        return

    # Update or add attributes
    new_attrs = {a.get("key"): a.get("value", {}).get("stringValue") for a in target_span.get("attributes", [])}
    new_attrs["ga5.receipt.id"] = receipt_id
    if status_val is not None:
        new_attrs["ga5.receipt.status"] = str(status_val)
    if result_class:
        new_attrs["ga5.result_class"] = str(result_class)
    if nonce:
        new_attrs["ga5.receipt.nonce"] = str(nonce)
    
    target_span["attributes"] = sanitize_attributes(new_attrs)
    target_span["endTimeUnixNano"] = now_unix_nano()

    # Set span status code: 1 = OK, 2 = ERROR
    if str(status_val) in ("503", "500", "408") or result_class in ("server_error", "transient_error", "timeout", "failed"):
        target_span["status"] = {"code": 2, "message": f"{result_class or 'error'} status {status_val}"}
    else:
        target_span["status"] = {"code": 1}
