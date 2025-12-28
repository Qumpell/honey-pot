import asyncssh
import asyncio

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT
from app.db import log_event
from app.fake_shell import FakeShell
from app.utils import now_iso, log, safe_parsed, sanitize_input, EventType, UNKNOWN, SupportedProtocols


class HoneySSHSession(asyncssh.SSHServerSession):
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
        loop = asyncio.get_event_loop()
        self._idle_task = loop.create_task(self._idle_watchdog())
        log.info("[SSH] Session channel opened")

    def _write(self, text: str):
        if self._chan:
            self._chan.write(text.replace("\n", "\r\n"))

    def shell_requested(self):
        peer = self.conn.get_extra_info("peername")
        ip = peer[0] if peer else UNKNOWN
        username = self.conn.get_extra_info("username") or UNKNOWN

        if not self.auth_manager.is_granted(ip):
            self._write("Login incorrect\n")
            return False

        self.shell = FakeShell(log, username=username)
        self._prompt = f"{username}@fakehost:{self.shell.cwd}$ "
        self._write("Welcome to Fake Honeypot Shell\n")
        self._write(self._prompt)
        return True


    def data_received(self, data, datatype):
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="ignore")
        else:
            text = str(data)
        text = text.replace("\x00", "")
        self._buffer += text
        asyncio.create_task(self._handle_buffer())

    async def _handle_buffer(self):
        lines = self._buffer.split("\n")
        self._buffer = lines.pop()
        for raw_line in lines:
            await self._handle_line(raw_line)

    async def _handle_line(self, raw_line: str):
        line = raw_line.rstrip("\r")
        line = sanitize_input(line, MAX_COMMAND_LENGTH)
        if not line:
            self._write(self._prompt)
            return

        self._cmd_count += 1
        log.info(f"[SSH] Command received (len={len(line)} count={self._cmd_count})")
        if self._cmd_count > MAX_COMMANDS_PER_SESSION:
            self._write("Session command limit reached. Goodbye.\n")
            self._chan.close()
            return

        if self.shell:
            await self._handle_shell_command(line)
        else:
            log.error(f"[SSH] Should never happen. FakeShell was not created.")

    async def _handle_shell_command(self, line: str):

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
            classification=EventType.COMMAND.value,
            confidence=0.7,
            details="{}",
            headers="{}",
        )

        res = self.shell.handle_line(line)

        if res == "__EXIT__":
            self._write("logout\n")
            self._chan.close()
            return

        if res:
            self._write(res)
        self._write(self._prompt)

    def eof_received(self):
        log.info("[SSH] EOF received")
        return True

    def connection_lost(self, exc):
        log.info("[SSH] Session closed")
        try:
            if self._idle_task and not self._idle_task.done():
                self._idle_task.cancel()
        except Exception:
            pass

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            if self._chan:
                self._write("Session timed out due to inactivity.\n")
                self._chan.close()
        except asyncio.CancelledError:
            log.error(f"[SSH] Should never happen. Session timed out due to inactivity.")
            pass
