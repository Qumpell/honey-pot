import os
from pathlib import Path

import asyncssh

from app.auth_manager import AuthManager
from app.config import HOST_KEY_PATH
from app.ssh_server import HoneySSHServer
from app.utils import log


async def ensure_host_key():
    path = Path(HOST_KEY_PATH)
    if not path.exists():
        log.info(f"[SSH] Generating host key at {path}")
        os.makedirs(path.parent, exist_ok=True)
        try:
            key = asyncssh.generate_private_key('ssh-rsa')
            key.write_private_key(str(path))
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
        except Exception as e:
            log.error(f"[SSH] Failed to generate host key: {e}")
            raise
    else:
        log.info(f"[SSH] Using existing host key: {path}")


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
