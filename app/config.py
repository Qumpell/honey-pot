import os

HOST_KEY_PATH = os.environ.get("HP_SSH_HOST_KEY", "data/ssh_host_key")
MAX_CONCURRENT_SESSIONS = int(os.environ.get("HP_MAX_CONNS", "50"))
MAX_COMMANDS_PER_SESSION = int(os.environ.get("HP_MAX_CMDS", "50"))
HISTORY_LIMIT = int(os.environ.get("HP_HISTORY_LIMIT", "20"))
MAX_COMMAND_LENGTH = int(os.environ.get("HP_MAX_CMD_LEN", "256"))
SESSION_IDLE_TIMEOUT = int(os.environ.get("HP_SESSION_TIMEOUT", "300"))
BRUTE_MIN = int(os.environ.get("HP_BRUTE_MIN", "3"))
BRUTE_MAX = int(os.environ.get("HP_BRUTE_MAX", "7"))
AUTH_RETENTION_PERIOD = int(os.environ.get("HP_BRUTE_MAX", "3600"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("HP_DB_PATH", os.path.join(BASE_DIR, "..", "data", "honeypot.db"))
# DB_PATH = os.environ.get("HP_DB_PATH", "/app/data/honeypot.db")
SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "..", "schema.sql")