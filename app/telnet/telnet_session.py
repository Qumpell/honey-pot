import asyncio
import codecs
import random
import time

from app.auth_manager import AuthManager
from app.config import MAX_COMMAND_LENGTH, MAX_COMMANDS_PER_SESSION, SESSION_IDLE_TIMEOUT, BRUTE_MAX, HISTORY_LIMIT
from app.db import log_event, PROM_SESSION_GAUGE
from app.fake_shell import FakeShell
from app.utils import now_iso, log, sanitize_input, EventType, SupportedProtocols, to_json, sanitize_identity, \
    hash_secret, Classification, UNKNOWN, classify_attempt, classify_command


class HoneyTelnetAuthHandler:
    def __init__(self, auth_manager: AuthManager, peer_info):
        self.auth_manager = auth_manager
        self.peer_info = peer_info

    async def authenticate(self, username, password, start_time):
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

        granted, attempts, threshold = await self.auth_manager.register_attempt(self.peer_info["ip"], sanitized_username)
        unique_users = self.auth_manager.get_user_count(self.peer_info["ip"])
        classification = classify_attempt(username, password, start_time, unique_users)

        await log_event(
            timestamp=now_iso(),
            src_ip=self.peer_info["ip"],
            src_port=self.peer_info["src_port"],
            dst_port=self.peer_info["dst_port"],
            protocol=SupportedProtocols.TELNET,
            event_type=EventType.AUTH_ATTEMPT,
            raw=f"{sanitized_username}:{password_hash}",
            parsed=parsed,
            classification=classification,
            confidence=1.0,
            details="{}",
            headers="{}",
        )

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
                protocol=SupportedProtocols.TELNET,
                event_type=EventType.AUTH_GRANTED,
                raw=f"{sanitized_username}:{password_hash}",
                parsed=parsed,
                classification=Classification.HONEYPOT_GRANT,
                confidence=1.0,
                details="{}",
                headers="{}",
            )
            return True
        else:
            return False


class HoneyTelnetSession:
    def __init__(self, reader, writer, peer_info, auth_manager: AuthManager):
        self.reader = reader
        self.writer = writer
        self.peer_info = peer_info
        self.auth_manager = auth_manager
        self.auth_handler = HoneyTelnetAuthHandler(auth_manager, peer_info)
        self._cmd_count = 0
        self._idle_task = None
        self._history = []
        self._history_index = 0
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
        self.shell = None
        self._prompt = ""
        self._closed = False
        self.auth_activity_detected = False
        self.start_time = time.time()

    def _reset_idle_timeout(self):
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_watchdog())

    async def _idle_watchdog(self):
        try:
            await asyncio.sleep(SESSION_IDLE_TIMEOUT)
            self._write("\r\nSession timed out. Closing connection.\r\n")
            if not self.writer.is_closing():
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


    async def _read_line(self, echo=True):
        line_buffer = ""
        self._history_index = len(self._history)

        while True:
            try:
                if len(line_buffer) > MAX_COMMAND_LENGTH:
                    self._write("\r\n-bash: command too long\r\n")
                    return ""

                data = await self.reader.read(1)
                if not data:
                    return None
                self._reset_idle_timeout()

                # A. Telnet IAC
                if data == b'\xff':
                    ret = await self._handle_telnet_iac(echo)
                    if ret == "__CTRL_C__":
                        return ""
                    continue

                # B. Ctrl+C
                if data == b'\x03':
                    if echo and self.shell:
                        self._prompt = self.shell.get_prompt()
                        self._write("^C\r\n")
                    return ""

                # C. Arrows
                if data == b'\x1b':
                    line_buffer = await self._handle_escape_sequence(line_buffer)
                    continue

                # D. Backspace
                if data in (b'\x08', b'\x7f'):
                    line_buffer = self._handle_backspace(line_buffer, echo)
                    continue

                if data in (b'\r', b'\n'):
                    return await self._handle_enter(data, line_buffer, echo)

                line_buffer = self._handle_printable_char(data, line_buffer, echo)

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
            if not username.strip():
                continue

            self.auth_activity_detected = True

            self._write("Password: ")
            password = await self._read_line(echo=False)
            if password is None:
                return False

            await self.auth_handler.authenticate(username, password, self.start_time)

            if self.auth_manager.is_granted(self.peer_info["ip"]):
                self.shell = FakeShell(log, username=username)
                self._prompt = self.shell.get_prompt()
                self._write("\n")
                self._write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\n\n")
                self._write(" * Documentation:  https://help.ubuntu.com\n")
                self._write(" * Management:     https://landscape.canonical.com\n")
                self._write(" * Support:        https://ubuntu.com/advantage\n\n")
                self._write(self._prompt)
                return True

            await asyncio.sleep(random.uniform(0.1, 0.5))
            self._write("\r\nLogin incorrect\r\n")

        return False

    async def _handle_command(self, line: str):
        line = sanitize_input(line.strip().replace("\r", ""), MAX_COMMAND_LENGTH)
        if not line:
            self._prompt = self.shell.get_prompt()
            self._write(self._prompt)
            return True

        self._cmd_count += 1
        log.info(f"[TELNET] Command received (len={len(line)} count={self._cmd_count})")

        if self._cmd_count > MAX_COMMANDS_PER_SESSION:
            self._write("\r\nSession command limit reached. Goodbye.\r\n")
            return False

        classification = classify_command(line)
        await log_event(
            timestamp=now_iso(),
            src_ip=self.peer_info["ip"],
            src_port=self.peer_info["src_port"],
            dst_port=self.peer_info["dst_port"],
            protocol=SupportedProtocols.TELNET,
            event_type=EventType.COMMAND,
            raw=line,
            parsed=to_json({"cmd": line}),
            classification=classification,
            confidence=1.0,
            details="{}",
            headers="{}",
        )

        res = self.shell.handle_line(line)

        if res == "__EXIT__":
            self._write("\r\nlogout\r\n")
            return False

        self._prompt = self.shell.get_prompt()
        if res:
            self._write(res)
        self._write(self._prompt)
        return True

    async def run(self):
        self._reset_idle_timeout()
        PROM_SESSION_GAUGE.labels(protocol=SupportedProtocols.TELNET.value).inc()
        self.writer.write(b'\xff\xfb\x01\xff\xfb\x03')
        try:
            if not await self._handle_login():
                return

            while True:
                line = await self._read_line()
                if line is None:
                    break

                if line == "__CTRL_C__":
                    self._prompt = self.shell.get_prompt()
                    self._write(self._prompt)
                    continue

                continue_session = await self._handle_command(line)
                if not continue_session:
                    break

        except Exception as e:
            log.error(f"[TELNET] Session error: {e}")
        finally:
            if not self.auth_activity_detected:
                await self._log_scan_event()
            PROM_SESSION_GAUGE.labels(protocol=SupportedProtocols.TELNET.value).dec()
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

    def _handle_backspace(self, line_buffer: str, echo: bool) -> str:
        if len(line_buffer) > 0:
            line_buffer = line_buffer[:-1]
            if echo:
                self.writer.write(b'\x08 \x08')
        return line_buffer

    async def _handle_history_navigation(self, direction: str, current_buffer: str) -> str:
        if not self._history:
            return current_buffer

        if direction == "UP":
            if self._history_index > 0:
                self._history_index -= 1
            else:
                return current_buffer
        elif direction == "DOWN":
            if self._history_index < len(self._history):
                self._history_index += 1
            else:
                return current_buffer

        for _ in range(len(current_buffer)):
            self.writer.write(b'\x08 \x08')
        new_buffer = ""
        if self._history_index < len(self._history):
            new_buffer = self._history[self._history_index]

        self.writer.write(new_buffer.encode('utf-8'))
        await self.writer.drain()
        return new_buffer

    async def _handle_escape_sequence(self, current_buffer: str) -> str:
        try:
            seq = await asyncio.wait_for(self.reader.read(2), timeout=0.1)
            if seq == b'[A':
                return await self._handle_history_navigation("UP", current_buffer)
            elif seq == b'[B':
                return await self._handle_history_navigation("DOWN", current_buffer)
        except asyncio.TimeoutError:
            pass
        return current_buffer

    async def _handle_enter(self, data, line_buffer, echo):
        if data == b'\r':
            try:
                nxt = await asyncio.wait_for(self.reader.read(1), timeout=0.01)
                if nxt != b'\n':
                    pass
            except:
                pass

        if echo:
            self._write("\r\n")

        clean_line = line_buffer.strip()

        if clean_line and echo:
            if not self._history or self._history[-1] != clean_line:
                self._history.append(clean_line)
                if len(self._history) > HISTORY_LIMIT:
                    self._history.pop(0)

        return line_buffer

    async def _handle_telnet_iac(self, echo):
        try:
            cmd = await self.reader.read(1)
            if cmd == b'\xf4':
                if echo:
                    self._prompt = self.shell.get_prompt()
                    self._write("^C\r\n")
                return "__CTRL_C__"

            if cmd in (b'\xfb', b'\xfc', b'\xfd', b'\xfe'):
                await self.reader.read(1)
        except Exception:
            pass
        return None

    def _handle_printable_char(self, data, line_buffer, echo):
        try:
            char = data.decode('utf-8')
            if char.isprintable():
                line_buffer += char
                if echo:
                    self.writer.write(data)
        except UnicodeDecodeError:
            pass
        return line_buffer

    async def _log_scan_event(self):
        if self.peer_info["ip"] == UNKNOWN:
            return

        is_aggressive = await self.auth_manager.check_aggressive_scan(self.peer_info["ip"])
        if await self.auth_manager.should_log_scan(self.peer_info["ip"]):
            detail_msg = "aggressive_nmap_style" if is_aggressive else "single_connection_probe"
            log.info(f"[SCAN] Detected {detail_msg} from {self.peer_info['ip']}")

            await log_event(
                timestamp=now_iso(),
                src_ip=self.peer_info["ip"],
                src_port=self.peer_info["src_port"],
                dst_port=self.peer_info["dst_port"],
                protocol=SupportedProtocols.TELNET,
                event_type=EventType.CONNECTION_CLOSED,
                raw="Connection closed without auth",
                parsed=to_json({"reason": "scan_detected"}),
                classification=Classification.SCANNING,
                confidence=1.0,
                details=to_json({"conn_frequency": "high" if is_aggressive else "low"}),
                headers="{}"
            )
        else:
            log.info(f"[TELNET] Scan event filtered by rate limit for {self.peer_info['ip']}")
