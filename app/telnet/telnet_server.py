import asyncio

from app.auth_manager import AuthManager
from app.config import MAX_CONCURRENT_SESSIONS
from app.telnet.telnet_session import HoneyTelnetSession
from app.utils import log, UNKNOWN

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
        if not self.server:
            return
        log.info("[TELNET] Stopping server and closing sessions...")
        self.server.close()
        if self.sessions:
            log.info(f"[TELNET] Force-closing {len(self.sessions)} active sessions...")
            for session in list(self.sessions):
                if session.writer and not session.writer.is_closing():
                    session.writer.close()
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *[s.writer.wait_closed() for s in self.sessions if s.writer],
                        return_exceptions=True
                    ),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                log.warning("[TELNET] Some sessions did not close in time, proceeding to shutdown")
        try:
            await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        log.info("[TELNET] Server stopped")

    async def _handle_connection(self, reader, writer):
        if _CONN_SEMAPHORE.locked():
            log.warning("[TELNET] Connection limit reached")
            writer.close()
            await writer.wait_closed()
            return

        try:
            await _CONN_SEMAPHORE.acquire()
        except asyncio.CancelledError:
            writer.close()
            return

        if writer.is_closing():
            _CONN_SEMAPHORE.release()
            log.debug("[TELNET] Connection closed while waiting for semaphore")
            return

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
