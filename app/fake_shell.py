import html
import os

from app.utils import UNKNOWN


class FakeShell:
    def __init__(self, logger, username=UNKNOWN):
        self.logger = logger
        self.username = username
        self.cwd = f"/home/{username}"
        self.hostname = "ubuntu"
        self.env = {
            "USER": username,
            "HOME": f"/home/{username}",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": self.cwd,
            "LANG": "en_US.UTF-8"
        }
        self.hist = []
        self._init_fs()

    def get_prompt(self):
        home = f"/home/{self.username}"
        if self.cwd == home:
            display_path = "~"
        elif self.cwd.startswith(home + "/"):
            display_path = "~" + self.cwd[len(home):]
        else:
            display_path = self.cwd
        return (
            f"\033[01;32m{self.username}@{self.hostname}\033[00m:"
            f"\033[01;34m{display_path}\033[00m$ "
        )

    def _init_fs(self):
        self.fs = {
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "proc", "root", "run", "sbin", "tmp", "usr", "var"],
            "/etc": ["passwd", "shadow", "hostname", "os-release", "apt", "network", "ssh"],
            "/home": [self.username],
            f"/home/{self.username}": ["README.txt", ".bash_history", ".bashrc", ".profile", ".ssh"],
            f"/home/{self.username}/.ssh": ["authorized_keys"],
            "/var": ["log", "mail", "run", "www"],
            "/proc": ["1", "cpuinfo", "meminfo", "version"]
        }

        self.files = {
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\n'
            ),
            "/etc/hostname": f"{self.hostname}\n",
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                f"{self.username}:x:1000:1000:{self.username}:/home/{self.username}:/bin/bash\n"
            ),
            f"/home/{self.username}/README.txt": "Restricted access environment. All activities are logged.\n",
            f"/home/{self.username}/.bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
            f"/home/{self.username}/.bash_history": "ls -la\nsudo su\napt update\n",
            "/proc/cpuinfo": "model name : Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu cores : 2\n",
            "/proc/meminfo": "MemTotal:        4012532 kB\nMemFree:         1245920 kB\n",
            "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"}

    def handle_line(self, line):
        line = line.strip()
        if not line: return ""

        self.hist.append(line)
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]

        if any(x in line for x in ("curl", "wget", "chmod +x", "python", "perl", "gcc")):
            pass

        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"

        elif cmd == "pwd":
            return self.cwd + "\n"

        elif cmd == "whoami":
            return self.username + "\n"

        elif cmd == "ls":
            return self._cmd_ls(args)

        elif cmd == "cd":
            return self._cmd_cd(args)

        elif cmd == "cat":
            return self._cmd_cat(args)

        elif cmd == "sudo":
            if not args: return "usage: sudo -h | -K | -k | -V\n"
            return f"[sudo] password for {self.username}: \nsorry, try again.\n"

        elif cmd == "uname":
            if "-a" in args:
                return "Linux ubuntu 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 15:03:00 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"

        elif cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 systemd\n"
                f" 1420 pts/0    00:00:00 bash\n"
                f" 1582 pts/0    00:00:00 ps\n"
            )

        elif cmd == "mkdir":
            if not args: return "mkdir: missing operand\n"
            new_dir = args[0]
            full_path = self._resolve_path(new_dir)
            parent = os.path.dirname(full_path)
            if parent in self.fs:
                self.fs.setdefault(full_path, [])
                if os.path.basename(full_path) not in self.fs[parent]:
                    self.fs[parent].append(os.path.basename(full_path))
                return ""
            return f"mkdir: cannot create directory '{new_dir}': No such file or directory\n"

        elif cmd == "history":
            return "".join(f" {i+1}  {h}\n" for i, h in enumerate(self.hist))

        return f"bash: {html.escape(cmd)}: command not found\n"

    def _cmd_ls(self, args):
        show_long = any("l" in arg for arg in args if arg.startswith("-"))
        show_all = any("a" in arg for arg in args if arg.startswith("-"))

        path_args = [a for a in args if not a.startswith("-")]
        target = self._resolve_path(path_args[0] if path_args else self.cwd)

        if target in self.fs:
            entries = self.fs[target].copy()
            if show_all:
                entries = [".", ".."] + entries

            entries.sort()

            if show_long:
                output = []
                if target == "/":
                    output.append(f"total {len(entries) * 4}")

                for entry in entries:
                    if entry == ".": e_path = target
                    elif entry == "..": e_path = "/".join(target.rstrip("/").split("/")[:-1]) or "/"
                    else: e_path = target.rstrip("/") + "/" + entry

                    output.append(self._get_file_details(entry, e_path))
                return "\n".join(output) + "\n"
            else:
                return "  ".join(entries) + "\n"

        return f"ls: cannot access '{path_args[0] if path_args else ''}': No such file or directory\n"

    def _get_file_details(self, name, full_path):
        is_dir = full_path in self.fs
        perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        links = "2" if is_dir else "1"
        owner = "root" if full_path.startswith(("/etc", "/var", "/bin")) else self.username
        group = owner
        if is_dir:
            size = 4096
        else:
            size = len(self.files.get(full_path, "")) or 512
        date_str = "Jan  2 12:00"
        return f"{perms} {links:>2} {owner:<8} {group:<8} {size:>8} {date_str} {name}"

    def _resolve_path(self, path):
        if path == "~":
            return f"/home/{self.username}"
        if path.startswith("/"):
            target = path
        else:
            target = self.cwd.rstrip("/") + "/" + path

        parts = target.split("/")
        actual_parts = []
        for p in parts:
            if p == "..":
                if actual_parts: actual_parts.pop()
            elif p == "." or p == "":
                continue
            else:
                actual_parts.append(p)
        return "/" + "/".join(actual_parts)

    def _cmd_mkdir(self, args):
        if not args: return "mkdir: missing operand\n"
        path = args[0]
        full_path = self._resolve_path(path)
        parent = "/".join(full_path.rstrip("/").split("/")[:-1])
        if parent == "": parent = "/"

        if parent in self.fs:
            if full_path not in self.fs:
                self.fs[full_path] = []
                base_name = full_path.split("/")[-1]
                if base_name not in self.fs[parent]:
                    self.fs[parent].append(base_name)
            return ""
        return f"mkdir: cannot create directory '{path}': No such file or directory\n"

    def _cmd_cat(self, args):
        if not args: return ""
        target = self._resolve_path(args[0])
        if target in self.files:
            content = self.files[target]
            return content if content.endswith("\n") else content + "\n"
        if target in self.fs:
            return f"cat: {args[0]}: Is a directory\n"
        return f"cat: {args[0]}: No such file or directory\n"

    def _cmd_cd(self, args):
        target_path = args[0] if args else "~"
        new_cwd = self._resolve_path(target_path)
        if new_cwd in self.fs:
            self.cwd = new_cwd
            self.env["PWD"] = self.cwd
            return ""
        return f"bash: cd: {target_path}: No such file or directory\n"