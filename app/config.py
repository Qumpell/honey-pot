import os

HOST_KEY_PATH = os.environ.get("HP_SSH_HOST_KEY", "data/ssh_host_key")
MAX_CONCURRENT_SESSIONS = int(os.environ.get("HP_MAX_CONNS", "50"))
MAX_COMMANDS_PER_SESSION = int(os.environ.get("HP_MAX_CMDS", "200"))
MAX_COMMAND_LENGTH = int(os.environ.get("HP_MAX_CMD_LEN", "256"))
SESSION_IDLE_TIMEOUT = int(os.environ.get("HP_SESSION_TIMEOUT", "300"))
HP_PARSED_JSON = os.environ.get("HP_PARSED_JSON", "1")
BRUTE_MIN = int(os.environ.get("HP_BRUTE_MIN", "3"))
BRUTE_MAX = int(os.environ.get("HP_BRUTE_MAX", "7"))