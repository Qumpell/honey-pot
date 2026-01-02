import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict

from app.utils import log, now_iso


class StatsManager:
    def __init__(self):
        self._counts: Dict[str, int] = defaultdict(int)
        self._total = 0
        self._first_seen: Optional[str] = None
        self._last_seen: Optional[str] = None
        self._current_day = datetime.now().strftime('%Y-%m-%d')
        self._lock = asyncio.Lock()
        self._dirty = False

    async def load_today_stats(self):
        from app.db import get_daily_summary
        try:
            data = await get_daily_summary(self._current_day)
            if data:
                async with self._lock:
                    self._total = data["total"]
                    self._counts = defaultdict(int, data["counts"])
                    self._first_seen = data["first_seen"]
                    self._last_seen = data["last_seen"]
                log.info(f"[STATS] Stats loaded for {self._current_day}")
        except Exception as e:
            log.error(f"[STATS] Load failed: {e}")

    async def register_event(self, classification: str):
        async with self._lock:
            today = datetime.now().strftime('%Y-%m-%d')
            if today != self._current_day:
                await self._flush_internal()
                self._reset(today)

            self._counts[classification] += 1
            self._total += 1
            now = now_iso()

            if not self._first_seen:
                self._first_seen = now
            self._last_seen = now
            self._dirty = True

    async def _flush_internal(self):
        from app.db import upsert_daily_summary
        if not self._dirty:
            return

        try:
            await upsert_daily_summary(
                day=self._current_day,
                counts=dict(self._counts),
                first_seen=self._first_seen,
                last_seen=self._last_seen,
                total=self._total
            )
            self._dirty = False
        except Exception as e:
            log.error(f"[STATS] Flush internal failed: {e}")

    def _reset(self, new_day):
        self._counts.clear()
        self._total = 0
        self._first_seen = None
        self._last_seen = None
        self._current_day = new_day
        self._dirty = False
        log.info(f"[STATS] Date rollover. New day: {new_day}")

    async def flush(self):
        async with self._lock:
            await self._flush_internal()

    async def run_background_saver(self, interval=15):
        log.info("[STATS] Background saver started")
        try:
            while True:
                await asyncio.sleep(interval)
                await self.flush()
        except asyncio.CancelledError:
            log.info("[STATS] Background saver stopping...")
            await self.flush()