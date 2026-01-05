import asyncio
import random
import time

from app.config import BRUTE_MIN, BRUTE_MAX, AUTH_RETENTION_PERIOD

class AuthManager:
    def __init__(self):
        self._attempts = {}
        self._thresholds = {}
        self._granted = set()
        self._lock = asyncio.Lock()
        self._tried_users = {}
        self._last_seen = {}
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        self._conn_history = {}
        self._last_scan_log = {}

    async def register_attempt(self, ip: str, username:str):
        async with self._lock:
            now = time.time()
            self._last_seen[ip] = now

            if username:
                if ip not in self._tried_users:
                    self._tried_users[ip] = set()
                self._tried_users[ip].add(username)

            cur = self._attempts.get(ip, 0) + 1
            self._attempts[ip] = cur

            if ip not in self._thresholds:
                self._thresholds[ip] = random.randint(BRUTE_MIN, BRUTE_MAX)
            threshold = self._thresholds[ip]

            if ip in self._granted:
                return True, cur, threshold

            if cur >= threshold:
                self._granted.add(ip)
                return True, cur, threshold

            return False, cur, threshold

    def is_granted(self, ip: str) -> bool:
        return ip in self._granted

    def get_user_count(self, ip: str) -> int:
        return len(self._tried_users.get(ip, set()))

    async def _periodic_cleanup(self):
        while True:
            await asyncio.sleep(1800)
            await self.cleanup_old_data()

    async def cleanup_old_data(self):
        async with self._lock:
            now = time.time()
            expiry_limit = now - AUTH_RETENTION_PERIOD

            expired_ips = [
                ip for ip, last_ts in self._last_seen.items()
                if last_ts < expiry_limit
            ]

            for ip in expired_ips:
                self._attempts.pop(ip, None)
                self._thresholds.pop(ip, None)
                self._tried_users.pop(ip, None)
                self._last_seen.pop(ip, None)
                self._granted.discard(ip)
                self._conn_history.pop(ip, None)
                self._last_scan_log.pop(ip, None)

            for ip in self._conn_history:
                self._conn_history[ip] = [ts for ts in self._conn_history[ip] if now - ts < 60]

            if expired_ips:
                from app.utils import log
                log.info(f"[AUTH] Cleaned up {len(expired_ips)} expired IP records from memory")

    async def close_cleaning_task(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                from app.utils import log
                log.debug("[AUTH] Cleanup task cancelled successfully")

    async def check_aggressive_scan(self, ip: str) -> bool:
        async with self._lock:
            now = time.time()
            if ip not in self._conn_history:
                self._conn_history[ip] = []

            self._conn_history[ip].append(now)
            self._conn_history[ip] = [ts for ts in self._conn_history[ip] if now - ts < 10]

            return len(self._conn_history[ip]) > 6

    async def should_log_scan(self, ip: str) -> bool:
        async with self._lock:
            now = time.time()
            last_log = self._last_scan_log.get(ip, 0)
            if now - last_log > 600:
                self._last_scan_log[ip] = now
                return True
            return False