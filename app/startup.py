import os
from pathlib import Path

import asyncssh

from app.auth_manager import AuthManager
from app.config import HOST_KEY_PATH
from app.ssh.ssh_server import HoneySSHServer
from app.telnet.telnet_server import HoneyTelnetServer
from app.utils import log


async def ensure_host_key():
    path = Path(HOST_KEY_PATH)
    if path.exists():
        log.info(f"[SSH] Using existing host key: {path}")
        return
    log.info(f"[SSH] Generating host key at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)

    key = asyncssh.generate_private_key('ssh-rsa')
    key.write_private_key(str(path))
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        log.warning(f"[SSH] Could not restrict permissions on {path}, skipping chmod")

async def start_ssh_honeypot(port=2222):
    auth_manager = AuthManager()
    await ensure_host_key()
    log.info(f"[SSH] Starting fake SSH server on port {port}...")
    return await asyncssh.listen(
        host="0.0.0.0",
        port=port,
        server_factory=lambda: HoneySSHServer(auth_manager=auth_manager),
        server_host_keys=[HOST_KEY_PATH],
        encoding='utf-8',
    )

async def start_telnet_honeypot(port=23):
    auth_manager = AuthManager()
    log.info(f"[TELNET] Starting fake Telnet server on port {port}...")
    server = HoneyTelnetServer(auth_manager=auth_manager)
    await server.start(host="0.0.0.0", port=port)
    return server
