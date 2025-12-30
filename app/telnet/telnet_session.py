import asyncio
import codecs

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT
from app.db import log_event
from app.fake_shell import FakeShell
from app.utils import now_iso, log, sanitize_input, EventType, UNKNOWN, SupportedProtocols, to_json, sanitize_identity, hash_secret, Classification


class HoneyTelnetAuthHandler:
    def __init__(self, auth_manager: AuthManager, peer_info):
        self.auth_manager = auth_manager
        self.peer_info = peer_info

    async def authenticate(self, username, password):
        sanitized_username = sanitize_identity(username)
        password_hash = hash_secret(password)
        log.info(
            "[TELNET] Password attempt user='%s' pass='<redacted>' (len=%d)",
            sanitized_username,
            len(password) if password else 0,
        )

        parsed = to_json({
            "username": sanitized_username,
            "password_hash": password_hash,
        })

        await log_event(
            timestamp=now_iso(),
            src_ip=self.peer_info["ip"],
            src_port=self.peer_info["src_port"],
            dst_port=self.peer_info["dst_port"],
            protocol=SupportedProtocols.TELNET.value,
            event_type=EventType.AUTH_ATTEMPT.value,
            raw=f"{sanitized_username}:{password_hash}",
            parsed=parsed,
            classification=Classification.PASSWORD_GUESS.value,
            confidence=0.9,
            details="{}",
            headers="{}",
        )

        granted, attempts, threshold = await self.auth_manager.register_attempt(self.peer_info["ip"])
        if not granted:
            return False

        log.info(
            "[TELNET] Granting fake shell to %s after %d/%d attempts",
            self.peer_info["ip"],
            attempts,
            threshold,
        )

        await log_event(
            timestamp=now_iso(),
            src_ip=self.peer_info["ip"],
            src_port=self.peer_info["src_port"],
            dst_port=self.peer_info["dst_port"],
            protocol=SupportedProtocols.TELNET.value,
            event_type=EventType.AUTH_GRANTED.value,
            raw=f"{sanitized_username}:{password_hash}",
            parsed=parsed,
            classification=Classification.HONEYPOT_GRANT.value,
            confidence=1.0,
            details="{}",
            headers="{}",
        )
        return True


class HoneyTelnetSession:
    def __init__(self, reader, writer, peer_info, auth_manager: AuthManager):
        self.reader = reader
        self.writer = writer
        self.peer_info = peer_info
        self.auth_manager = auth_manager
        self.auth_handler = HoneyTelnetAuthHandler(auth_manager, peer_info)

        self._cmd_count = 0
        self._idle_task = None
        self._buffer = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
        self.shell = None
        self._prompt = ""
        self._process_lock = asyncio.Lock()

        self._authenticated = False
        self._login_state = "username"  # username, password, authenticated

    def _reset_idle_timeout(self):
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_watchdog())

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            # await self._write("\r\nSession timed out. Closing connection.\r\n")
            self._write("\r\nSession timed out. Closing connection.\r\n")
            self.writer.close()
            await self.writer.wait_closed()
            log.info(f"[TELNET] Connection closed by watchdog for {self.peer_info['ip']}")
        except asyncio.CancelledError:
            pass

    def _write(self, text: str):
        if not self.writer.is_closing():
            # Telnet uses CRLF
            self.writer.write(text.replace("\n", "\r\n").encode('utf-8'))

    async def _read_line(self):
        """Read a line from the Telnet connection"""
        while True:
            try:
                data = await asyncio.wait_for(self.reader.read(1024), timeout=1.0)
                if not data:
                    return None  # Connection closed

                self._reset_idle_timeout()
                decoded = self._decoder.decode(data)
                self._buffer += decoded

                if "\n" in self._buffer or "\r" in self._buffer:
                    lines = self._buffer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                    self._buffer = lines.pop()
                    line = lines[0] if lines else ""
                    return line.strip()

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error(f"[TELNET] Read error: {e}")
                return None

    async def _handle_login(self):
        """Handle Telnet login process"""
        self._write("login: ")
        username = await self._read_line()
        if username is None:
            return False

        username = sanitize_input(username, 64)
        if not username:
            return False

        self._write("Password: ")
        password = await self._read_line()
        if password is None:
            return False

        # Authenticate
        authenticated = await self.auth_handler.authenticate(username, password)
        if not authenticated:
            self._write("\r\nLogin incorrect\r\n")
            return False

        # Setup shell
        self.shell = FakeShell(log, username=username)
        self._prompt = f"{username}@fakehost:{self.shell.cwd}$ "
        self._write("\r\nWelcome to Fake Honeypot Shell\r\n")
        self._write(self._prompt)
        return True

    async def _handle_command(self, line: str):
        """Handle a shell command"""
        line = sanitize_input(line.strip().replace("\r", ""), MAX_COMMAND_LENGTH)
        if not line:
            self._write(self._prompt)
            return True

        self._cmd_count += 1
        log.info(f"[TELNET] Command received (len={len(line)} count={self._cmd_count})")

        if self._cmd_count > MAX_COMMANDS_PER_SESSION:
            self._write("\r\nSession command limit reached. Goodbye.\r\n")
            return False

        # Log command
        await log_event(
            timestamp=now_iso(),
            src_ip=self.peer_info["ip"],
            src_port=self.peer_info["src_port"],
            dst_port=self.peer_info["dst_port"],
            protocol=SupportedProtocols.TELNET.value,
            event_type=EventType.COMMAND.value,
            raw=line,
            parsed=to_json({"cmd": line}),
            classification=EventType.COMMAND.value,
            confidence=0.7,
            details="{}",
            headers="{}",
        )

        # Process command
        res = self.shell.handle_line(line)

        if res == "__EXIT__":
            await self._write("\r\nlogout\r\n")
            return False

        if res:
            self._write(res)
        self._write(self._prompt)
        return True

    async def run(self):
        """Main session loop"""
        self._reset_idle_timeout()

        try:
            # Handle login
            if not await self._handle_login():
                return

            # Main command loop
            while True:
                line = await self._read_line()
                if line is None:
                    break

                continue_session = await self._handle_command(line)
                if not continue_session:
                    break

        except Exception as e:
            log.error(f"[TELNET] Session error: {e}")
        finally:
            if self._idle_task and not self._idle_task.done():
                self._idle_task.cancel()
            if not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()
