import asyncssh
import asyncio

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT
from app.db import log_event
from app.fake_shell import FakeShell
from app.utils import now_iso, log, safe_parsed


class HoneySSHSession(asyncssh.SSHServerSession):
    """Session object handling interactive shell commands."""

    def __init__(self, conn, auth_manager:AuthManager):
        self.conn = conn
        self._chan = None
        self._cmd_count = 0
        self._idle_task = None
        self._buffer = ""
        self.shell = None
        self._prompt = None
        self.auth_manager = auth_manager

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

        if not self.auth_manager.is_granted(ip):
            try:
                self._write("Login incorrect\n")
            except Exception:
                pass
            return False

        # Create the fake shell instance
        try:
            # also pass source/destination ports and protocol for accurate logging
            try:
                sock = self.conn.get_extra_info("sockname")
            except Exception:
                sock = None
            src_port = peer[1] if peer and len(peer) > 1 else 0
            dst_port = sock[1] if sock and len(sock) > 1 else 0
            self.shell = FakeShell(log, log_event, peer[0], src_port=src_port, dst_port=dst_port, protocol="ssh", username=username)
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
                            parsed=safe_parsed({"cmd": line}),
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
                        parsed=safe_parsed({"cmd": line}),
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
