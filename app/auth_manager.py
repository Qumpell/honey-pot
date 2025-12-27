import asyncio
import random
from app.config import BRUTE_MIN, BRUTE_MAX

class AuthManager:
    def __init__(self):
        self._attempts = {}
        self._thresholds = {}
        self._granted = set()
        self._lock = asyncio.Lock()

    async def register_attempt(self, ip: str):
        async with self._lock:
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