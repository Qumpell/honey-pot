import asyncio
import codecs

import asyncssh

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT
from app.db import log_event
from app.fake_shell import FakeShell
from app.utils import now_iso, log, sanitize_input, EventType, UNKNOWN, SupportedProtocols, to_json


class HoneySSHSession(asyncssh.SSHServerSession):
    def __init__(self, conn, auth_manager:AuthManager):
        self.conn = conn
        self._chan = None
        self._cmd_count = 0
        self._idle_task = None
        self._buffer = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
        self.shell = None
        self._prompt = ""
        self.auth_manager = auth_manager
        self._process_lock = asyncio.Lock()

    def connection_made(self, chan):
        self._chan = chan
        self._reset_idle_timeout()
        log.info("[SSH] Session channel opened")

    def _reset_idle_timeout(self):
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_watchdog())

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            if self.conn:
                self._write("\r\nSession timed out. Closing connection.\r\n")
                self.conn.close()
                log.info(f"[SSH] Connection closed by watchdog for {self.conn.get_extra_info('peername')}")
        except asyncio.CancelledError:
            pass

    def data_received(self, data, datatype):
        self._reset_idle_timeout()
        if isinstance(data, bytes):
            if data == b'\x03':
                self._write("^C\r\n" + self._prompt)
                self._buffer = ""
                return
            self._buffer += self._decoder.decode(data)
        else:
            self._buffer += str(data)
        task = asyncio.create_task(self._process_buffer())
        task.add_done_callback(lambda t: log.error(f"Buffer error: {t.exception()}") if t.exception() else None)

    async def _process_buffer(self):
        async with self._process_lock:
            if "\n" in self._buffer:
                lines = self._buffer.split("\n")
                self._buffer = lines.pop()
                for raw_line in lines:
                    await self._handle_line(raw_line)

    async def _handle_line(self, raw_line: str):
        line = sanitize_input(raw_line.strip().replace("\r", ""), MAX_COMMAND_LENGTH)
        if not line:
            self._write(self._prompt)
            return

        self._cmd_count += 1
        log.info(f"[SSH] Command received (len={len(line)} count={self._cmd_count})")

        if self._cmd_count > MAX_COMMANDS_PER_SESSION:
            self._write("\r\nSession command limit reached. Goodbye.\r\n")
            if self.conn:
                self.conn.close()
            self._chan = None
            self._cmd_count = 0
            return

        if self.shell:
            await self._handle_shell_command(line)
        else:
            log.error(f"[SSH] Should never happen. FakeShell was not created.")

    async def _handle_shell_command(self, line: str):
        peer = self._get_peer_info()
        await log_event(
            timestamp=now_iso(),
            src_ip=peer["ip"],
            src_port=peer["src_port"],
            dst_port=peer["dst_port"],
            protocol=SupportedProtocols.SSH.value,
            event_type=EventType.COMMAND.value,
            raw=line,
            parsed=to_json({"cmd": line}),
            classification=EventType.COMMAND.value,
            confidence=0.7,
            details="{}",
            headers="{}",
        )

        res = self.shell.handle_line(line)

        if res == "__EXIT__":
            self._write("\r\nlogout\r\n")
            if self.conn:
                self.conn.close()
            self._chan = None
            self._cmd_count = 0
            return

        if res:
            self._write(res)
        self._write(self._prompt)

    def _write(self, text: str):
        if self._chan and not self._chan.is_closing():
            self._chan.write(text.replace("\n", "\r\n"))

    def shell_requested(self):
        peer = self._get_peer_info()
        ip = peer["ip"]
        username = self.conn.get_extra_info("username") or UNKNOWN

        if not self.auth_manager.is_granted(ip):
            self._write("\r\nLogin incorrect\r\n")
            return False

        self.shell = FakeShell(log, username=username)
        self._prompt = f"\033[01;32m{username}@ubuntu\033[00m:\033[01;34m{self.shell.cwd}\033[00m$ "
        banner = (
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
        )
        self._write(banner)
        self._write(self._prompt)
        return True

    def eof_received(self):
        log.info("[SSH] EOF received")
        return True

    def connection_lost(self, exc):
        log.info("[SSH] Session closed")
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()

    def _get_peer_info(self):
        peer = self.conn.get_extra_info("peername") or ()
        sock = self.conn.get_extra_info("sockname") or ()
        return {
            "ip": peer[0] if len(peer) > 0 else UNKNOWN,
            "src_port": peer[1] if len(peer) > 1 else 0,
            "dst_port": sock[1] if len(sock) > 1 else 0,
        }