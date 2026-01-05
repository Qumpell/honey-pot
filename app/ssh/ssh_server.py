import asyncio
import time

import asyncssh

from app.auth_manager import AuthManager
from app.config import MAX_CONCURRENT_SESSIONS
from app.db import log_event
from app.ssh.ssh_session import HoneySSHSession
from app.utils import now_iso, log, EventType, SupportedProtocols, Classification, UNKNOWN, normalize_str, \
    classify_attempt
from app.utils import sanitize_identity, to_json, hash_secret

_CONN_SEMAPHORE = asyncio.BoundedSemaphore(MAX_CONCURRENT_SESSIONS)

class HoneySSHServer(asyncssh.SSHServer):
    _all_connections = set()

    def __init__(self, auth_manager: AuthManager):
        super().__init__()
        self.conn = None
        self._acquired_semaphore = False
        self.auth_manager = auth_manager
        self.auth_activity_detected = False
        self.start_time = time.time()


    def connection_made(self, conn):
        self.conn = conn
        HoneySSHServer._all_connections.add(conn)
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
        self.auth_activity_detected = True
        peer = self._get_peer_info()

        sanitized_username = sanitize_identity(username)
        password_hash = hash_secret(password)

        granted, attempts, threshold = await self.auth_manager.register_attempt(peer["ip"], sanitized_username)
        user_count = self.auth_manager.get_user_count(self._get_peer_info()["ip"])
        classification = classify_attempt(username, password, self.start_time, user_count)

        parsed = to_json({
            "username": sanitized_username,
            "password_hash": password_hash,
        })

        log.info(
            "[SSH] Password attempt user='%s' pass='<redacted>' (len=%d)",
            sanitized_username,
            len(password) if password else 0,
        )

        return await self._handle_auth_attempt(
            peer=peer,
            event_attempt=EventType.AUTH_ATTEMPT,
            event_granted=EventType.AUTH_GRANTED,
            raw=f"{sanitized_username}:{password_hash}",
            parsed=parsed,
            classification_attempt=classification,
            granted_info=(granted, attempts, threshold),
        )

    async def validate_public_key(self, username, key):
        self.auth_activity_detected = True
        peer = self._get_peer_info()

        fp = key.get_fingerprint('sha256')
        fingerprint = normalize_str(fp)
        sanitized_username = sanitize_identity(username)

        granted, attempts, threshold = await self.auth_manager.register_attempt(peer["ip"], sanitized_username)
        user_count = self.auth_manager.get_user_count(self._get_peer_info()["ip"])
        classification = Classification.PUBKEY_GUESS
        if user_count > 3:
            classification = Classification.CREDENTIAL_STUFFING

        log.info("[SSH] Public key attempt user='%s' key='%s'", sanitized_username, fingerprint)

        parsed = to_json({"username": sanitized_username, "pub_key": fp})

        return await self._handle_auth_attempt(
            peer=peer,
            event_attempt=EventType.AUTH_ATTEMPT_PUBKEY,
            event_granted=EventType.AUTH_GRANTED_PUBKEY,
            raw=f"{sanitized_username}:{fingerprint}",
            parsed=parsed,
            classification_attempt=classification,
            granted_info=(granted, attempts, threshold)
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
            granted_info,
            confidence_attempt=1.0,
    ):

        granted, attempts, threshold = granted_info

        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH,
            event_type=event_attempt,
            raw=raw,
            parsed=parsed,
            classification=classification_attempt,
            confidence=confidence_attempt,
            details="{}",
            headers="{}",
        )

        if not granted:
            return False

        log.info("[SSH] Granting fake shell to %s (%d/%d)", peer["ip"], attempts, threshold)

        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH,
            event_type=event_granted,
            raw=raw,
            parsed=parsed,
            classification=Classification.HONEYPOT_GRANT,
            confidence=1.0,
            details=to_json({"attempts": attempts, "threshold": threshold}),
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
        HoneySSHServer._all_connections.discard(self.conn)
        if not self.auth_activity_detected:
            peer = self._get_peer_info()
            asyncio.create_task(self._log_scan_event(peer))
        if self._acquired_semaphore:
            _CONN_SEMAPHORE.release()
            self._acquired_semaphore = False

    @classmethod
    async def close_all_sessions(cls):
        if not cls._all_connections:
            return
        log.info(f"[SSH] Force-closing {len(cls._all_connections)} sessions...")
        for conn in list(cls._all_connections):
            conn.close()
        await asyncio.gather(*[c.wait_closed() for c in cls._all_connections], return_exceptions=True)

    async def _log_scan_event(self, peer):
        if peer["ip"] == UNKNOWN:
            return

        log.info(f"[SSH] Detected SCAN/PROBE from {peer['ip']} (Disconnect without auth)")

        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH,
            event_type=EventType.CONNECTION_CLOSED,
            raw="Connection closed without auth",
            parsed=to_json({"reason": "scan_detected"}),
            classification=Classification.SCANNING,
            confidence=1.0,
            details='{"tool": "nmap_likely"}',
            headers="{}"
        )