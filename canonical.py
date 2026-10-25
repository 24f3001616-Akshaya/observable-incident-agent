import json
import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Any

def canonical(obj: Any) -> str:
    """Canonical JSON serialization: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(obj: Any) -> str:
    """SHA-256 digest of canonical JSON representation."""
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()

def hex_id(nbytes: int = 8) -> str:
    """Generate cryptographically secure random hexadecimal string.
    Default 8 bytes (16 hex characters) for span IDs; use 16 bytes (32 hex chars) for trace IDs.
    """
    return secrets.token_hex(nbytes)

def valid_id(value: Any) -> bool:
    """Check if value is a valid opaque ID string with length >= 8."""
    return isinstance(value, str) and len(value.strip()) >= 8

def now_iso() -> str:
    """Current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def now_unix_nano() -> str:
    """Current UTC timestamp in Unix epoch nanoseconds (as string)."""
    return str(int(time.time() * 1e9))
