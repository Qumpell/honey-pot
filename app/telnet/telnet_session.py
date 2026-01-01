import asyncio
import codecs

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT, BRUTE_MAX
from app.db import log_event
from app.fake_shell import FakeShell
from app.utils import now_iso, log, sanitize_input, EventType, SupportedProtocols, to_json, sanitize_identity, \
    hash_secret, Classification, process_telnet_data


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
        if granted:
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
        self._closed = False

    def _reset_idle_timeout(self):
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_watchdog())

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            self._write("\r\nSession timed out. Closing connection.\r\n")
            if not self.writer.is_closing():
                # self.writer.close()
                # await self.writer.wait_closed()
                await self._close()
            log.info(f"[TELNET] Connection closed by watchdog for {self.peer_info['ip']}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"[TELNET] Watchdog error: {e}")

    def _write(self, text: str):
        if not self.writer.is_closing():
            data = text.replace("\n", "\r\n").encode('utf-8')
            self.writer.write(data)


    async def _read_line(self):
        while True:
            try:
                data = await self.reader.read(1024)
                if not data:
                    return None

                self._reset_idle_timeout()
                clean_data = process_telnet_data(data)
                decoded = self._decoder.decode(clean_data)
                self._buffer += decoded

                if "\n" in self._buffer or "\r" in self._buffer:
                    lines = self._buffer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                    self._buffer = lines.pop()
                    line = lines[0] if lines else ""
                    return line.strip()

            except ConnectionResetError:
                return None
            except Exception as e:
                log.error(f"[TELNET] Read error: {e}")
                return None

    async def _handle_login(self):
        for _ in range(BRUTE_MAX):
            self._write("login: ")
            username = await self._read_line()
            if username is None:
                return False

            username = sanitize_input(username, 64)
            if not username:
                continue

            self._write("Password: ")
            password = await self._read_line()
            if password is None:
                return False

            await self.auth_handler.authenticate(username, password)

            if self.auth_manager.is_granted(self.peer_info["ip"]):
                self.shell = FakeShell(log, username=username)
                self._prompt = f"{username}@fakehost:{self.shell.cwd}$ "
                self._write("\r\nWelcome to Fake Honeypot Shell\r\n")
                self._write(self._prompt)
                return True

            self._write("\r\nLogin incorrect\r\n")

        return False

    async def _handle_command(self, line: str):
        line = sanitize_input(line.strip().replace("\r", ""), MAX_COMMAND_LENGTH)
        if not line:
            self._write(self._prompt)
            return True

        self._cmd_count += 1
        log.info(f"[TELNET] Command received (len={len(line)} count={self._cmd_count})")

        if self._cmd_count > MAX_COMMANDS_PER_SESSION:
            # self._cmd_count = MAX_COMMANDS_PER_SESSION
            self._write("\r\nSession command limit reached. Goodbye.\r\n")
            return False

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

        res = self.shell.handle_line(line)

        if res == "__EXIT__":
            self._write("\r\nlogout\r\n")
            return False

        if res:
            self._write(res)
        self._write(self._prompt)
        return True

    async def run(self):
        self._reset_idle_timeout()

        try:
            if not await self._handle_login():
                return

            while True:
                line = await self._read_line()
                if line is None:
                    break

                self._write(line + "\n")
                continue_session = await self._handle_command(line)
                if not continue_session:
                    break

        except Exception as e:
            log.error(f"[TELNET] Session error: {e}")
        finally:
            if self._idle_task and not self._idle_task.done():
                self._idle_task.cancel()
            if not self.writer.is_closing():
                await self._close()

    async def _close(self):
        if self._closed:
            return
        self._closed = True

        if not self.writer.is_closing():
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except ConnectionResetError:
                pass