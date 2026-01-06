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
    MALWARE_DOWNLOAD = "malware_download"
    RECONNAISSANCE = "reconnaissance"
    CRITICAL_ACTIVITY = "critical_activity"
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
    duration = time.time() - start_time
    combined = f"{username}:{password}"

    patterns = {
        "log4shell": r"\$\{(jndi|ctx):",
        "sql_injection": r"(union|select|or\s+1=1|--|;|drop\s+table)",
        "path_traversal": r"(\.\./|\.\.\\|/etc/passwd|/windows/system32)",
        "web_shell": r"(<\?php|base64_decode|eval\(|passthru|shell_exec)",
        "binary_payload": r"(\\x[0-9a-f]{2}){4,}"
    }

    for name, pattern in patterns.items():
        if re.search(pattern, combined, re.IGNORECASE):
            log.warning(f"[ALARM] Detect {name} in auth attempt from {username}")
            return Classification.EXPLOIT_ATTEMPT

    if unique_user_count > 3:
        return Classification.CREDENTIAL_STUFFING

    if duration < 0.5:
        return Classification.BOT_HARVESTING

    return Classification.PASSWORD_GUESS

def classify_command(line: str) -> Classification:
    line = line.strip().lower()
    parts = set(line.split())
    if not parts:
        return Classification.COMMAND_EXEC

    malware_tools = {"wget", "curl", "tftp", "ftpget", "scp", "sftp", "busybox"}
    if (parts & malware_tools) or any(p in line for p in ("http://", "https://", "ftp://")):
        return Classification.MALWARE_DOWNLOAD

    recon_cmds = {"uname", "id", "whoami", "ifconfig", "ip", "df", "free", "lsb_release", "netstat", "ps"}
    recon_files = {"/etc/shadow", "/etc/passwd", "/etc/issue", "/proc/cpuinfo", "/proc/mounts"}
    if (parts & recon_cmds) or any(f in line for f in recon_files):
        return Classification.RECONNAISSANCE

    if (
            any(p in line for p in ("bash -i", "nc -e", "/dev/tcp/")) or
            ("python" in parts and any(x in line for x in ("socket", "http", "exec", "subprocess"))) or
            ("perl" in parts and "-e" in parts) or
            ("php" in parts and "-r" in parts)
    ):
        return Classification.CRITICAL_ACTIVITY

    if "rm" in parts and "-f" in line and ("-r" in line or "/" in line):
        return Classification.CRITICAL_ACTIVITY

    if "chmod" in parts and any(x in line for x in ("+x", "777", "755")):
        return Classification.CRITICAL_ACTIVITY

    if "nohup" in parts or any(x in line for x in ("mine.sh", "cryptonight", "xmrig")):
        return Classification.CRITICAL_ACTIVITY

    return Classification.COMMAND_EXEC
