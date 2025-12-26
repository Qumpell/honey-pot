from datetime import datetime,timezone

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def is_blank(s :str) -> bool:
    return s is None or s.strip() == ""