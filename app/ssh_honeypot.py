import os
import asyncio
import asyncssh
from pathlib import Path
from app.db import log_event
from app.utils import now_iso
import logging
import random

# Import the FakeShell implementation you created
from app.fake_shell import FakeShell

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)
log = logging.getLogger("honeypot")
asyncssh_logger = logging.getLogger('asyncssh')
asyncssh_logger.setLevel(logging.DEBUG)

# Configurable paths and limits
HOST_KEY_PATH = os.environ.get("HP_SSH_HOST_KEY", "data/ssh_host_key")
MAX_CONCURRENT_SESSIONS = int(os.environ.get("HP_MAX_CONNS", "50"))
MAX_COMMANDS_PER_SESSION = int(os.environ.get("HP_MAX_CMDS", "200"))
MAX_COMMAND_LENGTH = int(os.environ.get("HP_MAX_CMD_LEN", "2048"))
SESSION_IDLE_TIMEOUT = int(os.environ.get("HP_SESSION_TIMEOUT", "300"))

# Simple semaphore to limit concurrent connections
_CONN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)

# Track auth attempts per source IP and random thresholds to simulate
# "brute-force into shell" behavior. These are in-memory only.
_IP_ATTEMPTS = {}
_IP_THRESHOLDS = {}
_IP_GRANTED = set()
_IP_LOCK = asyncio.Lock()

# Configurable brute-forcing thresholds
BRUTE_MIN = int(os.environ.get("HP_BRUTE_MIN", "3"))
BRUTE_MAX = int(os.environ.get("HP_BRUTE_MAX", "7"))


async def _register_attempt(ip: str):
    """Increment attempts for `ip`, set a random threshold if needed,
    and return (granted: bool, attempts: int, threshold: int).
    """
    async with _IP_LOCK:
        cur = _IP_ATTEMPTS.get(ip, 0) + 1
        _IP_ATTEMPTS[ip] = cur
        if ip not in _IP_THRESHOLDS:
            _IP_THRESHOLDS[ip] = random.randint(BRUTE_MIN, BRUTE_MAX)
        threshold = _IP_THRESHOLDS[ip]
        if ip in _IP_GRANTED:
            return True, cur, threshold
        if cur >= threshold:
            _IP_GRANTED.add(ip)
            return True, cur, threshold
        return False, cur, threshold


async def ensure_host_key():
    """Generate SSH host key if it doesn't exist and set safe permissions.

    This function is intentionally forgiving on Windows file permission steps.
    """
    path = Path(HOST_KEY_PATH)
    if not path.exists():
        log.info(f"[SSH] Generating host key at {path}")
        os.makedirs(path.parent, exist_ok=True)
        try:
            key = asyncssh.generate_private_key('ssh-rsa')
            # asyncssh key objects expose write_private_key
            key.write_private_key(str(path))
            try:
                # Restrict file permissions when possible
                os.chmod(path, 0o600)
            except Exception:
                # Not critical on Windows
                pass
        except Exception as e:
            log.error(f"[SSH] Failed to generate host key: {e}")
            raise
    else:
        log.info(f"[SSH] Using existing host key: {path}")


async def start_ssh_honeypot(port=2222):
    await ensure_host_key()
    log.info(f"[SSH] Starting fake SSH server on port {port}...")
    return await asyncssh.listen(
        host="0.0.0.0",
        port=port,
        server_factory=HoneySSHServer,
        server_host_keys=[HOST_KEY_PATH],
        encoding='utf-8',
    )


class HoneySSHServer(asyncssh.SSHServer):
    """Handles authentication attempts."""

    def __init__(self):
        super().__init__()
        self.conn = None
        # Track if this connection has acquired the global semaphore
        self._acquired_semaphore = False

    def connection_made(self, conn):
        self.conn = conn
        # Acquire a slot for concurrent connections. If the semaphore is
        # exhausted this will queue — keeping memory bounded.
        try:
            acquired = _CONN_SEMAPHORE.acquire_nowait()
        except Exception:
            # If acquire_nowait is not available or fails, schedule an acquire
            asyncio.create_task(_CONN_SEMAPHORE.acquire())
            acquired = True
        self._acquired_semaphore = bool(acquired)

    def begin_auth(self, username):
        log.info(f"[SSH] begin_auth for username '{username}'")
        # Returning True forces password or pubkey attempts (even without valid accounts)
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        # Avoid printing raw secrets to console logs; keep them only in DB.
        log.info(f"[SSH] Password attempt user='{username}' pass='<redacted>' (len={len(password) if password else 0})")
        try:
            peer = self.conn.get_extra_info(f"peername")
            sock = self.conn.get_extra_info("sockname")
            await log_event(
                timestamp=now_iso(),
                src_ip=peer[0],
                src_port=peer[1],
                dst_port=sock[1],
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

        # Register the attempt and decide whether to "grant" a fake account
        try:
            peer = self.conn.get_extra_info("peername")
            ip = peer[0]
        except Exception:
            ip = "unknown"

        try:
            granted, attempts, threshold = await _register_attempt(ip)
        except Exception:
            granted = False

        if granted:
            log.info(f"[SSH] Granting fake shell to {ip} after {attempts}/{threshold} attempts")
            try:
                await log_event(
                    timestamp=now_iso(),
                    src_ip=ip,
                    src_port=peer[1] if peer and len(peer) > 1 else 0,
                    dst_port=sock[1] if sock and len(sock) > 1 else 0,
                    protocol="ssh",
                    event_type="auth_granted",
                    raw=f"{username}:<redacted>",
                    parsed=f'{{"user": "{username}"}}',
                    classification="honeypot_grant",
                    confidence=1.0,
                    details='{}',
                    headers='{}'
                )
            except Exception:
                pass
            return True

        return False

    async def validate_public_key(self, username, key):
        # asyncssh may return the fingerprint as `str` or `bytes` depending
        # on versions/encoding. Handle both safely.
        fp = key.get_fingerprint('sha256')
        if isinstance(fp, bytes):
            try:
                fingerprint = fp.decode('utf-8')
            except Exception:
                fingerprint = repr(fp)
        else:
            fingerprint = str(fp)
        log.info(f"[SSH] Public key attempt user='{username}' key='{fingerprint}'")
        try:
            peer = self.conn.get_extra_info("peername")
            sock = self.conn.get_extra_info("sockname")
            await log_event(
                timestamp=now_iso(),
                src_ip=peer[0],
                src_port=peer[1],
                dst_port=sock[1],
                protocol="ssh",
                event_type="auth_attempt_pubkey",
                raw=fingerprint,
                parsed=f'{{"user": "{username}"}}',
                classification="pubkey_guess",
                confidence=0.9,
                details='{"fingerprint_type":"sha256"}',
                headers="{}"
            )
            log.info("[DB] Logged pubkey attempt")
        except Exception as e:
            log.error(f"[DB] Failed to log pubkey attempt: {e}")
        # Register attempt and possibly grant fake shell access
        try:
            peer = self.conn.get_extra_info("peername")
            ip = peer[0]
        except Exception:
            ip = "unknown"

        try:
            granted, attempts, threshold = await _register_attempt(ip)
        except Exception:
            granted = False

        if granted:
            log.info(f"[SSH] Granting fake shell to {ip} after {attempts}/{threshold} attempts (pubkey)")
            try:
                await log_event(
                    timestamp=now_iso(),
                    src_ip=ip,
                    src_port=peer[1] if peer and len(peer) > 1 else 0,
                    dst_port=sock[1] if sock and len(sock) > 1 else 0,
                    protocol="ssh",
                    event_type="auth_granted_pubkey",
                    raw=fingerprint,
                    parsed=f'{{"user": "{username}"}}',
                    classification="honeypot_grant",
                    confidence=1.0,
                    details='{}',
                    headers='{}'
                )
            except Exception:
                pass
            return True

        return False

    def session_requested(self):
        log.info("[SSH] Shell session requested")
        # Pass the underlying connection object to the session so it can
        # access peer information safely.
        return HoneySSHSession(self.conn)


class HoneySSHSession(asyncssh.SSHServerSession):
    """Session object handling interactive shell commands."""

    def __init__(self, conn):
        self.conn = conn
        self._chan = None
        self._cmd_count = 0
        self._idle_task = None
        self._buffer = ""
        self.shell = None
        self._prompt = None

    def connection_made(self, chan):
        self._chan = chan
        log.info("[SSH] Session channel opened")
        # Start an inactivity timer to close the session if idle for too long
        try:
            loop = asyncio.get_event_loop()
            self._idle_task = loop.create_task(self._idle_watchdog())
        except Exception:
            self._idle_task = None

    def _write(self, text: str):
        """Write text to the channel converting LF->CRLF for terminal compatibility."""
        if not self._chan:
            return
        try:
            if text is None:
                return
            if not isinstance(text, str):
                text = str(text)
            # Normalize newlines to CRLF which most terminals expect
            text = text.replace('\n', '\r\n')
            self._chan.write(text)
        except Exception:
            try:
                # best-effort swallow
                pass
            except Exception:
                pass

    def shell_requested(self):
        # Instantiate the FakeShell only for connections that were granted
        try:
            peer = self.conn.get_extra_info("peername")
            ip = peer[0]
        except Exception:
            ip = "unknown"

        username = self.conn.get_extra_info("username") or "unknown"

        if ip not in _IP_GRANTED:
            # In case a session is requested without being granted, reject.
            try:
                self._write("Login incorrect\n")
            except Exception:
                pass
            return False

        # Create the fake shell instance
        try:
            self.shell = FakeShell(log, log_event, peer[0], username=username)
            self._prompt = f"{username}@fakehost:{self.shell.cwd}$ "
            try:
                self._write("Welcome to Fake Honeypot Shell\n")
                self._write("Type commands, they will be logged.\n\n")
                self._write(self._prompt)
            except Exception as e:
                log.error(f"[SSH] Failed to write initial prompt: {e}")
            return True
        except Exception as e:
            log.error(f"[SSH] Failed to create FakeShell: {e}")
            return False

    def data_received(self, data, datatype):
        # Schedule async handling to avoid asyncssh calling a coroutine
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(self._handle_data(data, datatype))
        except Exception:
            try:
                asyncio.create_task(self._handle_data(data, datatype))
            except Exception:
                log.exception("Failed to schedule _handle_data task")

    async def _handle_data(self, data, datatype):
        # Normalize incoming data to string and sanitize.
        if isinstance(data, bytes):
            try:
                cmd = data.decode('utf-8', errors='ignore')
            except Exception:
                cmd = str(data)
        else:
            cmd = str(data)
        # Accumulate into buffer and only process full lines
        self._buffer += cmd
        lines = self._buffer.split('\n')
        # Keep last incomplete line in buffer
        if not self._buffer.endswith('\n'):
            self._buffer = lines.pop()
        else:
            self._buffer = ""

        for line in lines:
            line = line.rstrip('\r')
            line = line.strip()

            # Enforce length limits to avoid abuse
            if len(line) > MAX_COMMAND_LENGTH:
                line = line[:MAX_COMMAND_LENGTH] + "..."

            self._cmd_count += 1
            log.info(f"[SSH] Command received (len={len(line)} count={self._cmd_count})")

            # If too many commands, close the session politely
            if self._cmd_count > MAX_COMMANDS_PER_SESSION:
                try:
                    self._write("Session command limit reached. Goodbye.\n")
                    self._chan.close()
                except Exception:
                    pass
                return

            # If fake shell exists, delegate handling; otherwise just log and respond
            if self.shell:
                try:
                    # Log via FakeShell helper (it will call db logger)
                    try:
                        self.shell._log_cmd(line)
                    except Exception:
                        # Fallback DB logging
                        peer = self.conn.get_extra_info("peername")
                        sock = self.conn.get_extra_info("sockname")
                        await log_event(
                            timestamp=now_iso(),
                            src_ip=peer[0],
                            src_port=peer[1],
                            dst_port=sock[1],
                            protocol="ssh",
                            event_type="command",
                            raw=line,
                            parsed=f'{{"cmd": "{line}"}}',
                            classification="command",
                            confidence=0.7,
                            details='{}',
                            headers='{}'
                        )

                    res = self.shell.handle_line(line)
                    if res == "__EXIT__":
                        try:
                            self._write("logout\n")
                            self._chan.close()
                        except Exception:
                            pass
                        return
                    else:
                        # Write command output and reprint prompt
                        try:
                            if res:
                                self._write(res)
                            self._write(self._prompt)
                        except Exception:
                            pass
                except Exception as e:
                    log.error(f"[SSH] FakeShell handling error: {e}")
                    try:
                        self._write("Internal error\n")
                        self._write(self._prompt or "$ ")
                    except Exception:
                        pass
            else:
                # No shell (shouldn't happen for granted sessions) — log and reply
                try:
                    peer = self.conn.get_extra_info("peername")
                    sock = self.conn.get_extra_info("sockname")
                    await log_event(
                        timestamp=now_iso(),
                        src_ip=peer[0],
                        src_port=peer[1],
                        dst_port=sock[1],
                        protocol="ssh",
                        event_type="command",
                        raw=line,
                        parsed=f'{{"cmd": "{line}"}}',
                        classification="command",
                        confidence=0.7,
                        details='{}',
                        headers='{}'
                    )
                except Exception:
                    pass
                try:
                    self._write(f"bash: {line}: command not found\n")
                except Exception:
                    pass

    def eof_received(self):
        log.info("[SSH] EOF received")
        return True

    def connection_lost(self, exc):
        log.info("[SSH] Session closed")
        # Cancel idle watchdog
        try:
            if self._idle_task and not self._idle_task.done():
                self._idle_task.cancel()
        except Exception:
            pass
        # release semaphore slot if acquired (best-effort)
        try:
            _CONN_SEMAPHORE.release()
        except Exception:
            pass

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            try:
                        if self._chan:
                            self._write("Session timed out due to inactivity.\n")
                            self._chan.close()
            except Exception:
                pass
        except asyncio.CancelledError:
            return
