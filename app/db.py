import asyncio
import json
import os
from typing import Optional, Dict

import aiosqlite

from app.config import SCHEMA_FILE, DB_PATH
from app.stats import StatsManager
from app.utils import Classification, EventType, SupportedProtocols

_DB_CONN: Optional[aiosqlite.Connection] = None
_DB_LOCK = asyncio.Lock()

_STATS_MANAGER: Optional['StatsManager'] = None

def set_stats_manager(manager):
    global _STATS_MANAGER
    _STATS_MANAGER = manager

SQLITE_PRAGMAS = [
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("foreign_keys", "ON"),
    ("busy_timeout", "5000"), 
]

async def _apply_pragmas(conn: aiosqlite.Connection):
    for k, v in SQLITE_PRAGMAS:
        await conn.execute(f"PRAGMA {k} = {v}")
    await conn.commit()

async def init_db(db_path: str = DB_PATH):
    global _DB_CONN
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    if _DB_CONN is not None:
        return _DB_CONN
    
    conn = await aiosqlite.connect(db_path, timeout=5.0)
    await _apply_pragmas(conn)
    
    schema_path = SCHEMA_FILE
    if os.path.exists(schema_path):
        with open(schema_path, "r", encoding="utf-8") as f:
            sql = f.read()
            await conn.executescript(sql)
    else:
         await conn.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            day TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            event_type TEXT,
            raw TEXT,
            parsed TEXT,
            classification TEXT,
            confidence REAL,
            details TEXT,
            headers TEXT
        );
        CREATE TABLE IF NOT EXISTS daily_summary (
            day TEXT PRIMARY KEY,
            total_events INTEGER,
            by_class TEXT,
            first_seen TEXT,
            last_seen TEXT
        );
        """)
    await conn.commit()
    _DB_CONN = conn
    return _DB_CONN


async def close_db():
    global _DB_CONN
    if _DB_CONN:
        try:
            await _DB_CONN.close()
        except Exception:
            pass
        _DB_CONN = None
        
async def log_event(timestamp: str,
                    src_ip: str,
                    src_port: int,
                    dst_port: int,
                    protocol: SupportedProtocols,
                    event_type: EventType,
                    raw: str,
                    parsed: str = "",
                    classification: Classification = Classification.UNKNOWN,
                    confidence: float = 0.0,
                    details: str = "{}",
                    headers: str = "{}"):

    classification_str = classification.value
    protocol_str = protocol.value
    event_type_str = event_type.value
    global _DB_CONN
    if _DB_CONN is None:
        await init_db()

    day = timestamp.split("T")[0] if "T" in timestamp else timestamp[:10]
    async with _DB_LOCK:
        await _DB_CONN.execute("""
            INSERT INTO logs
            (timestamp, day, src_ip, src_port, dst_port, protocol, event_type,
             raw, parsed, classification, confidence, details, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, day, src_ip, src_port, dst_port, protocol_str, event_type_str,
            raw, parsed, classification_str, confidence, details, headers
        ))
        await _DB_CONN.commit()

    if _STATS_MANAGER:
        asyncio.create_task(_STATS_MANAGER.register_event(classification_str))
        
async def upsert_daily_summary(day: str,
                               counts: Dict[str, int],
                               first_seen: Optional[str],
                               last_seen: Optional[str],
                               total: int):
    global _DB_CONN
    if _DB_CONN is None:
        await init_db()

    by_class_json = json.dumps(counts)
    async with _DB_LOCK:
        try:
            await _DB_CONN.execute("""
                INSERT INTO daily_summary (day, total_events, by_class, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(day) DO UPDATE SET
                    total_events = excluded.total_events,
                    by_class = excluded.by_class,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen
            """, (day, total, by_class_json, first_seen, last_seen))
        except Exception:
            await _DB_CONN.execute("""
                REPLACE INTO daily_summary (day, total_events, by_class, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (day, total, by_class_json, first_seen, last_seen))
        await _DB_CONN.commit()
        
async def query_recent_logs(limit: int = 50):
    global _DB_CONN
    if _DB_CONN is None:
        await init_db()
    async with _DB_LOCK:
        cur = await _DB_CONN.execute("""
            SELECT id, timestamp, day, src_ip, src_port, dst_port, protocol,
                   event_type, raw, parsed, classification, confidence, details, headers
            FROM logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = await cur.fetchall()
        cols = [d[0] for d in cur.description]
        result = [dict(zip(cols, row)) for row in rows]
        await cur.close()
        return result        
    
async def query_logs_by_type(event_type: str, limit: int = 100):
    global _DB_CONN
    if _DB_CONN is None:
        await init_db()
    async with _DB_LOCK:
        cur = await _DB_CONN.execute("""
            SELECT id, timestamp, src_ip, raw, parsed, classification FROM logs
            WHERE event_type = ?
            ORDER BY id DESC LIMIT ?
        """, (event_type, limit))
        rows = await cur.fetchall()
        cols = [d[0] for d in cur.description]
        res = [dict(zip(cols, row)) for row in rows]
        await cur.close()
        return res

async def get_daily_summary(day: str):
    global _DB_CONN
    if _DB_CONN is None:
        await init_db()

    async with _DB_LOCK:
        async with _DB_CONN.execute(
                "SELECT total_events, by_class, first_seen, last_seen FROM daily_summary WHERE day = ?",
                (day,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "total": row[0],
                    "counts": json.loads(row[1]),
                    "first_seen": row[2],
                    "last_seen": row[3]
                }
    return None

