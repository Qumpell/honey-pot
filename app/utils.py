import json
import os
from datetime import datetime,timezone
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)
log = logging.getLogger("honeypot")
asyncssh_logger = logging.getLogger('asyncssh')
asyncssh_logger.setLevel(logging.DEBUG)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def is_blank(s :str) -> bool:
    return s is None or s.strip() == ""

def safe_parsed(obj):
    """Return a JSON string for `obj` when HP_PARSED_JSON is enabled.

    If the flag is disabled, return a minimal hand-escaped JSON-like string.
    This function never raises.
    """
    try:
        flag = os.environ.get("HP_PARSED_JSON", "1")
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
