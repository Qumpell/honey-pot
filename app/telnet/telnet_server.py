import asyncio
import codecs

from app.auth_manager import AuthManager
from app.config import MAX_CONCURRENT_SESSIONS
from app.db import log_event
from app.telnet.telnet_session import HoneyTelnetSession, HoneyTelnetAuthHandler
from app.utils import now_iso, log, EventType, SupportedProtocols, Classification, UNKNOWN, normalize_str
from app.utils import sanitize_identity, to_json, hash_secret

_CONN_SEMAPHORE = asyncio.BoundedSemaphore(MAX_CONCURRENT_SESSIONS)


class HoneyTelnetServer:
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
        self.server = None
        self.sessions = set()

    async def start(self, host="0.0.0.0", port=23):
        log.info(f"[TELNET] Starting fake Telnet server on port {port}...")
        self.server = await asyncio.start_server(
            self._handle_connection,
            host=host,
            port=port
        )
        log.info(f"[TELNET] Server listening on {host}:{port}")
        return self.server

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            log.info("[TELNET] Server stopped")

    async def _handle_connection(self, reader, writer):
        if _CONN_SEMAPHORE.locked():
            log.warning("[TELNET] Connection limit reached")
            writer.close()
            await writer.wait_closed()
            return

        await _CONN_SEMAPHORE.acquire()

        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("sockname")
        peer_info = {
            "ip": peer[0] if peer else UNKNOWN,
            "src_port": peer[1] if peer and len(peer) > 1 else 0,
            "dst_port": sock[1] if sock and len(sock) > 1 else 0,
        }

        log.info(f"[TELNET] New connection from {peer_info['ip']}:{peer_info['src_port']}")

        session = HoneyTelnetSession(
            reader=reader,
            writer=writer,
            peer_info=peer_info,
            auth_manager=self.auth_manager
        )
        self.sessions.add(session)

        try:
            await session.run()
        except Exception as e:
            log.error(f"[TELNET] Session error: {e}")
        finally:
            self.sessions.discard(session)
            _CONN_SEMAPHORE.release()
            log.info(f"[TELNET] Connection closed for {peer_info['ip']}:{peer_info['src_port']}")
