import asyncio

import asyncssh

from app.auth_manager import AuthManager
from app.config import MAX_CONCURRENT_SESSIONS
from app.db import log_event
from app.ssh.ssh_session import HoneySSHSession
from app.utils import now_iso, log, EventType, SupportedProtocols, Classification, UNKNOWN, normalize_str
from app.utils import sanitize_identity, to_json, hash_secret

_CONN_SEMAPHORE = asyncio.BoundedSemaphore(MAX_CONCURRENT_SESSIONS)

class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, auth_manager: AuthManager):
        super().__init__()
        self.conn = None
        self._acquired_semaphore = False
        self.auth_manager = auth_manager

    def connection_made(self, conn):
        self.conn = conn
        if _CONN_SEMAPHORE.locked():
            log.warning("[SSH] Connection limit reached")
            conn.close()
            return
        asyncio.create_task(self._acquire_semaphore())

    async def _acquire_semaphore(self):
        try:
            await _CONN_SEMAPHORE.acquire()
            if self.conn.is_closed():
                log.debug("[SSH] Connection closed while waiting for semaphore - Released")
                _CONN_SEMAPHORE.release()
                return

            self._acquired_semaphore = True
        except Exception as e:
            log.error(f"[SSH] Error in semaphore acquisition: {e}")
            if not self.conn.is_closed():
                self.conn.close()

    def begin_auth(self, username):
        log.info(
            "[SSH] begin_auth for username '%s'",
            sanitize_identity(username),
        )
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        sanitized_username = sanitize_identity(username)
        password_hash = hash_secret(password)
        log.info(
            "[SSH] Password attempt user='%s' pass='<redacted>' (len=%d)",
            sanitized_username,
            len(password) if password else 0,
        )
        peer = self._get_peer_info()
        parsed = to_json({
            "username": sanitized_username,
            "password_hash": password_hash,
        })
        return await self._handle_auth_attempt(
            peer=peer,
            event_attempt=EventType.AUTH_ATTEMPT.value,
            event_granted=EventType.AUTH_GRANTED.value,
            raw=f"{sanitized_username}:{password_hash}",
            parsed=parsed,
            classification_attempt=Classification.PASSWORD_GUESS.value,
            classification_granted=Classification.HONEYPOT_GRANT.value,
        )

    async def validate_public_key(self, username, key):
        fp = key.get_fingerprint('sha256')
        fingerprint = normalize_str(fp)
        sanitized_username = sanitize_identity(username)
        log.info(
            "[SSH] Public key attempt user='%s' key='%s'",
            sanitized_username,
            fingerprint,
        )
        peer = self._get_peer_info()
        parsed = to_json({
            "username": sanitized_username,
            "pub_key": fingerprint,
        })
        return await self._handle_auth_attempt(
            peer=peer,
            event_attempt=EventType.AUTH_ATTEMPT_PUBKEY.value,
            event_granted=EventType.AUTH_GRANTED_PUBKEY.value,
            raw=f"{sanitized_username}:{fingerprint}",
            parsed=parsed,
            classification_attempt=Classification.PUBKEY_GUESS.value,
            classification_granted=Classification.HONEYPOT_GRANT.value,
        )

    async def _handle_auth_attempt(
            self,
            *,
            peer,
            event_attempt,
            event_granted,
            raw,
            parsed,
            classification_attempt,
            classification_granted,
            confidence_attempt=0.9,
    ):
        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH.value,
            event_type=event_attempt,
            raw=raw,
            parsed=parsed,
            classification=classification_attempt,
            confidence=confidence_attempt,
            details="{}",
            headers="{}",
        )

        granted, attempts, threshold = await self.auth_manager.register_attempt(peer["ip"])
        if not granted:
            return False

        log.info(
            "[SSH] Granting fake shell to %s after %d/%d attempts",
            peer["ip"],
            attempts,
            threshold,
        )

        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH.value,
            event_type=event_granted,
            raw=raw,
            parsed=parsed,
            classification=classification_granted,
            confidence=1.0,
            details="{}",
            headers="{}",
        )
        return True

    def _get_peer_info(self):
        peer = self.conn.get_extra_info("peername") or ()
        sock = self.conn.get_extra_info("sockname") or ()
        return {
            "ip": peer[0] if len(peer) > 0 else UNKNOWN,
            "src_port": peer[1] if len(peer) > 1 else 0,
            "dst_port": sock[1] if len(sock) > 1 else 0,
        }

    def session_requested(self):
        log.info("[SSH] Shell session requested")
        return HoneySSHSession(self.conn, auth_manager=self.auth_manager)

    def connection_lost(self, exc):
        if self._acquired_semaphore:
            _CONN_SEMAPHORE.release()
            self._acquired_semaphore = False
