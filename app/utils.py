import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from enum import Enum


class EventType(Enum):
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_ATTEMPT_PUBKEY = "auth_attempt_pubkey"
    AUTH_GRANTED = "auth_granted"
    AUTH_GRANTED_PUBKEY = "auth_granted_pubkey"
    COMMAND = "command"
    CONNECTION_CLOSED = "connection_lost"

class Classification(Enum):
    PASSWORD_GUESS = "password_guess"
    PUBKEY_GUESS = "pubkey_guess"
    HONEYPOT_GRANT = "honeypot_grant"
    COMMAND_EXEC = "command_exec"
    SCANNING = "scanning"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    BOT_HARVESTING = "bot_harvesting"
    CREDENTIAL_STUFFING = "credential_stuffing"
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

def classify_attempt(username, password, start_time, unique_user_count) -> Classification:
    exploit_patterns = ["${", "jndi:", "SELECT ", "UNION ", "OR 1=1", "0x"]
    combined = (username + password).lower()
    if any(p in combined for p in exploit_patterns):
        return Classification.EXPLOIT_ATTEMPT

    if unique_user_count > 3:
        return Classification.CREDENTIAL_STUFFING;

    duration = time.time() - start_time
    if duration < 1.0:
        return Classification.BOT_HARVESTING

    return Classification.PASSWORD_GUESS
