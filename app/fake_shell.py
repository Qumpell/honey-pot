import asyncio
import html
import json
import os

import app.utils as utils

class FakeShell:
    def __init__(self, logger, db_log_func, peer_ip, src_port=0, dst_port=0, protocol="ssh", username="unknown"):
        self.logger = logger
        self.log_event = db_log_func
        self.peer_ip = peer_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.username = username
        self.cwd = "/home/" + username
        self.env = {"USER": username, "HOME": f"/home/{username}", "SHELL": "/bin/bash"}
        self.hist = []
        # A tiny fake FS (in-memory)
        self.fs = {
            "/": ["home", "etc", "var", "tmp"],
            f"/home/{username}": ["README", ".bash_history"],
            "/etc": ["os-release", "passwd"],
        }
        self.files = {
            f"/home/{username}/README": "This is a fictional honeypot user home.\n",
            "/etc/os-release": 'NAME="FakeOS"\nVERSION="1.0 (honeypot)"\n',
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
            f"/home/{username}/.bash_history": ""
        }

    def _log_cmd(self, raw_cmd, parsed=None, src_port=None, dst_port=None, protocol=None):
        # log to DB without printing secrets to console
        if utils.is_blank(raw_cmd):
            self.logger.debug("[DB] Blank command, not logging")
            return
        try:
            # Timestamp and db logging - make sure db_log_func matches your interface
                # Build parsed payload optionally as real JSON behind a feature flag
            try:
                    parsed_flag = os.environ.get("HP_PARSED_JSON", "1")
                    if parsed is not None:
                        parsed_value = parsed
                    elif parsed_flag in ("1", "true", "True"):
                        try:
                            parsed_value = json.dumps({"cmd": raw_cmd, "cwd": self.cwd}, ensure_ascii=False)
                        except Exception:
                            # Fallback to simple escaped string if json fails
                            parsed_value = json.dumps({"cmd": str(raw_cmd)})
                    else:
                        parsed_value = f'{{"cmd": "{html.escape(raw_cmd)}"}}'
            except Exception:
                    parsed_value = f'{{"cmd": "{html.escape(raw_cmd)}"}}'

            # allow caller overrides, else use values from the FakeShell instance
            sp = src_port if src_port is not None else self.src_port
            dp = dst_port if dst_port is not None else self.dst_port
            proto = protocol if protocol is not None else self.protocol

            coro = self.log_event(
                    timestamp=utils.now_iso(),
                    src_ip=self.peer_ip,
                    src_port=sp,
                    dst_port=dp,
                    protocol=proto,
                    event_type="command",
                    raw=raw_cmd,
                    parsed=parsed_value,
                    classification="command",
                    confidence=0.7,
                    details="{}",
                    headers="{}"
                )
            # Schedule coroutine instead of calling it directly to avoid
            # "coroutine was never awaited" warnings and to not block the
            # current sync caller.
            try:
                loop = asyncio.get_running_loop()
            except Exception:
                loop = None
            if loop is not None and loop.is_running():
                task = loop.create_task(coro)
                # Attach a callback to surface exceptions from the background task
                def _on_done(t):
                    try:
                        t.result()
                    except Exception as ex:
                        self.logger.error("[DB] Background log_event failed: %s", ex)

                task.add_done_callback(_on_done)
            else:
                # Best-effort fallback: run it synchronously (rare)
                try:
                    asyncio.run(coro)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error("[DB] Failed to log command: %s", e)

    def handle_line(self, line):
        line = line.strip()
        if not line:
            return ""
        # record history
        self.hist.append(line)
        # simple tokenization
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]

        # built-in commands
        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"

        if cmd == "pwd":
            return self.cwd + "\n"

        if cmd == "whoami":
            return self.username + "\n"

        if cmd == "id":
            uid = 1000
            gid = 1000
            return f"uid={uid}({self.username}) gid={gid}({self.username}) groups=1000({self.username})\n"

        if cmd == "ls":
            target = self.cwd if not args else (args[0] if args[0].startswith("/") else self.cwd + "/" + args[0])
            entries = self.fs.get(target)
            if entries is None:
                return f"ls: cannot access '{args[0] if args else ''}': No such file or directory\n"
            return "  ".join(entries) + "\n"

        if cmd == "cd":
            target = args[0] if args else self.env.get("HOME")
            if not target.startswith("/"):
                target = self.cwd.rstrip("/") + "/" + target
            # simple normalization
            if target.endswith("/."):
                target = target[:-2]
            if target in self.fs:
                self.cwd = target
                return ""
            return f"bash: cd: {args[0] if args else ''}: No such file or directory\n"

        if cmd == "cat":
            target = args[0] if args else ""
            if not target.startswith("/"):
                target = self.cwd.rstrip("/") + "/" + target
            content = self.files.get(target)
            if content is None:
                return f"cat: {args[0] if args else ''}: No such file or directory\n"
            return content

        if cmd == "history":
            out = ""
            for i, h in enumerate(self.hist[-100:], start=1):
                out += f" {i}  {h}\n"
            return out

        if cmd in ("uname", "uname -a"):
            return "Linux fakehost 5.15.0-0-fake #1 SMP Tue Jan 1 00:00:00 UTC 2025 x86_64 GNU/Linux\n"

        if cmd == "ps":
            # return a small plausible ps output
            pids = [(1, "init"), (1000, self.username), (2020, "sshd"), (3030, "bash")]
            lines = "  PID TTY          TIME CMD\n"
            for pid, name in pids:
                lines += f"  {pid} pts/0    00:00:00 {name}\n"
            return lines

        if cmd == "netstat" or cmd == "ss":
            return ("Proto Recv-Q Send-Q Local Address:Port Peer Address:Port State\n"
                    "tcp        0      0 0.0.0.0:22           0.0.0.0:*       LISTEN\n")

        if cmd == "echo":
            return " ".join(args) + "\n"

        if cmd == "help" or cmd == "?":
            return ("Supported commands: ls cd pwd cat whoami id history uname ps netstat echo help exit\n")

        # Unknown command: realistic response
        return f"bash: {html.escape(cmd)}: command not found\n"