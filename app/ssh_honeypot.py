import os
import asyncssh
from app.db import log_event
from app.utils import now_iso
import logging


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)
log = logging.getLogger("honeypot")


HOST_KEY_PATH = os.environ.get("HP_SSH_HOST_KEY", "data/ssh_host_key")

async def ensure_host_key():
    """Generate SSH host key if it doesn't exist."""
    if not os.path.exists(HOST_KEY_PATH):
        log.info(f"[SSH] Generating host key at {HOST_KEY_PATH}")
        print(f"[SSH] Generating host key at {HOST_KEY_PATH} ...")
        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        key = asyncssh.generate_private_key('ssh-rsa')
        key.write_private_key(HOST_KEY_PATH)
    else:
        log.info(f"[SSH] Using existing host key: {HOST_KEY_PATH}")



async def start_ssh_honeypot(port=2222):
    await ensure_host_key()
    log.info(f"[SSH] Starting fake SSH server on port {port}...")
    return await asyncssh.listen(
        host="0.0.0.0",
        port=port,
        server_factory=HoneySSHServer,
        server_host_keys=[HOST_KEY_PATH],
        encoding=None
    )
    

class HoneySSHServer(asyncssh.SSHServer):
    """Handles authentication attempts."""

    def __init__(self):
        super().__init__()

    def begin_auth(self, username):
        log.info(f"[SSH] begin_auth for username '{username}'")
        # Returning True forces password or pubkey attempts (even without valid accounts)
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        log.info(f"[SSH] Password attempt user='{username}' pass='{password}'")
        try:
            await log_event(
            timestamp=now_iso(),
            src_ip=self._conn.get_extra_info("peername")[0],
            src_port=self._conn.get_extra_info("peername")[1],
            dst_port=self._conn.get_extra_info("sockname")[1],
            protocol="ssh",
            event_type="auth_attempt",
            raw=f"{username}:{password}",
            parsed='{"user": "%s"}' % username,
            classification="password_guess",
            confidence=0.9,
            details='{}',
            headers='{}'
            )
            log.info("[DB] Logged password attempt")
        except Exception as e:
            log.error(f"[DB] Failed to log password attempt: {e}")

        # Always deny
        return False

    async def validate_public_key(self, username, key):
        log.info(f"[SSH] Public key attempt user='{username}' key='{key}'")
        try:
            await log_event(
                timestamp=now_iso(),
                src_ip=self._conn.get_extra_info("peername")[0],
                src_port=self._conn.get_extra_info("peername")[1],
                dst_port=self._conn.get_extra_info("sockname")[1],
                protocol="ssh",
                event_type="auth_attempt_pubkey",
                raw=str(key),
                parsed=f'{{"user": "{username}"}}',
                classification="pubkey_guess",
                confidence=0.9,
                details="{}",
                headers="{}"
            )
            log.info("[DB] Logged pubkey attempt")
        except Exception as e:
            log.error(f"[DB] Failed to log pubkey attempt: {e}")
        return False

    def session_requested(self):
        log.info("[SSH] Shell session requested")
        return HoneySSHSession(self._conn)



class HoneySSHSession(asyncssh.SSHServerSession):
    """Session object handling interactive shell commands."""

    def __init__(self, conn):
        self.conn = conn
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        log.info("[SSH] Session channel opened")

    async def shell_requested(self):
        self._chan.write("Welcome to Fake Honeypot Shell\n")
        self._chan.write("Type commands, they will be logged.\n\n")
        return True

    async def data_received(self, data, datatype):
        cmd = data.strip()
        log.info(f"[SSH] Command received: {cmd}")

        # Log command
        try:
            await log_event(
                timestamp=now_iso(),
                src_ip=self.conn.get_extra_info("peername")[0],
                src_port=self.conn.get_extra_info("peername")[1],
                dst_port=self.conn.get_extra_info("sockname")[1],
                protocol="ssh",
                event_type="command",
                raw=cmd,
                parsed=f'{{"cmd": "{cmd}"}}',
                classification="command",
                confidence=0.7,
                details='{}',
                headers='{}'
            )
            log.info("[DB] Logged command")
        except Exception as e:
            log.error(f"[DB] Failed to log command: {e}")

        # Fake terminal response
        self._chan.write(f"bash: {cmd}: command not found\n")

    def eof_received(self):
        log.info("[SSH] EOF received")
        return True

    def connection_lost(self, exc):
        log.info("[SSH] Session closed")
        pass