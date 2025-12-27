import asyncio
import os
from pathlib import Path
import asyncssh
from app.auth_manager import AuthManager
from app.config import MAX_CONCURRENT_SESSIONS, HOST_KEY_PATH
from app.db import log_event
from app.ssh_session import HoneySSHSession
from app.utils import now_iso, safe_parsed, log

_CONN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)


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
    auth_manager = AuthManager()
    await ensure_host_key()
    log.info(f"[SSH] Starting fake SSH server on port {port}...")
    return await asyncssh.listen(
        host="0.0.0.0",
        port=port,
        server_factory=lambda: HoneySSHServer(auth_manager=auth_manager),
        server_host_keys=[HOST_KEY_PATH],
        encoding='utf-8',
    )


class HoneySSHServer(asyncssh.SSHServer):
    """Handles authentication attempts."""

    def __init__(self, auth_manager: AuthManager):
        super().__init__()
        self.conn = None
        self._acquired_semaphore = False
        self.auth_manager = auth_manager

    def connection_made(self, conn):
        self.conn = conn
        # Acquire a slot for concurrent connections. If the semaphore is
        # exhausted this will queue — keeping memory bounded.
        try:
            # Prefer non-blocking acquire if available
            acquired = _CONN_SEMAPHORE.acquire_nowait()
            self._acquired_semaphore = bool(acquired)
        except AttributeError:
            # older asyncio may not expose acquire_nowait; schedule an acquire
            asyncio.create_task(_CONN_SEMAPHORE.acquire())
            self._acquired_semaphore = True
        except Exception:
            # Fallback: schedule an acquire and mark as acquired
            try:
                asyncio.create_task(_CONN_SEMAPHORE.acquire())
                self._acquired_semaphore = True
            except Exception:
                self._acquired_semaphore = False

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
                parsed=safe_parsed({"user": username}),
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
            granted, attempts, threshold = await self.auth_manager.register_attempt(ip)
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
                    parsed=safe_parsed({"user": username}),
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
                parsed=safe_parsed({"user": username}),
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
            granted, attempts, threshold = await self.auth_manager.register_attempt(ip)
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
                    parsed=safe_parsed({"user": username}),
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
        return HoneySSHSession(self.conn, auth_manager=self.auth_manager)

    def connection_lost(self, exc):
        # Release the semaphore slot if we acquired it when the connection ends
        try:
            if getattr(self, '_acquired_semaphore', False):
                _CONN_SEMAPHORE.release()
                self._acquired_semaphore = False
        except Exception:
            pass

