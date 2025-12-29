import json
import logging
import re
import hashlib
from datetime import datetime, timezone
from enum import Enum

from typing_extensions import deprecated

from app.config import HP_PARSED_JSON


class EventType(Enum):
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_ATTEMPT_PUBKEY = "auth_attempt_pubkey"
    AUTH_GRANTED = "auth_granted"
    AUTH_GRANTED_PUBKEY = "auth_granted_pubkey"
    COMMAND = "command"
    CONNECTION_LOST = "connection_lost"

class Classification(Enum):
    PASSWORD_GUESS = "password_guess"
    PUBKEY_GUESS = "pubkey_guess"
    HONEYPOT_GRANT = "honeypot_grant"
    COMMAND_EXEC = "command_exec"
    UNKNOWN = "unknown"

class SupportedProtocols(Enum):
    SSH = "ssh"
    TELNET = "telnet"

UNKNOWN = "unknown"

_ANSI_ESCAPE_RE = re.compile(
    r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
)

def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    logging.getLogger("asyncssh").setLevel(logging.DEBUG)
    return logging.getLogger("honeypot")

log = setup_logging()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def is_blank(s :str) -> bool:
    return s is None or s.strip() == ""

#todo to be removed
def safe_parsed(obj):
    """Return a JSON string for `obj` when HP_PARSED_JSON is enabled.

    If the flag is disabled, return a minimal hand-escaped JSON-like string.
    This function never raises.
    """
    try:
        flag = HP_PARSED_JSON
        if flag in ("1", "true", "True"):
            try:
                return json.dumps(obj, ensure_ascii=False)
            except Exception:
                # fallback to str-wrapped dict
                return json.dumps({"value": str(obj)})
        # default: return a simple string representation
        if isinstance(obj, dict):
            # make a safe simple representation
            try:
                # only include stringified values
                simple = {k: str(v) for k, v in obj.items()}
                return json.dumps(simple, ensure_ascii=False)
            except Exception:
                return json.dumps({"value": str(obj)})
        return json.dumps({"value": str(obj)})
    except Exception:
        try:
            return json.dumps({"value": str(obj)})
        except Exception:
            return '{"value":"<error>"}'

def to_json(data):
    try:
        return json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError):
        log.error("Should never happen. Failed to convert {} to JSON".format(data))
        return "{}"

def sanitize_input(value: str, max_len: int=1024) -> str:
    value = normalize_str(value)
    value = value[:max_len]
    value = value.replace('\x00', '')
    value = _ANSI_ESCAPE_RE.sub("", value)
    return "".join(c if c.isprintable() else " " for c in value)

def normalize_str(value:object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def hash_secret(value: str) -> str:
    if not value:
        return UNKNOWN
    return hashlib.blake2b(
        value.encode("utf-8", errors="ignore"),
        digest_size=16
    ).hexdigest()

def sanitize_identity(value: str, max_len=64) -> str:
    if not value:
        return UNKNOWN
    value = value[:max_len]
    value = value.replace("\x00", "")
    return "".join(c if c.isprintable() else "_" for c in value)


