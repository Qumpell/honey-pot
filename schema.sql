PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    day TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_logs_day ON logs (day);
CREATE INDEX IF NOT EXISTS idx_logs_srcip ON logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_eventtype ON logs (event_type);

CREATE TABLE IF NOT EXISTS daily_summary (
    day TEXT PRIMARY KEY,
    total_events INTEGER,
    by_class TEXT,
    first_seen TEXT,
    last_seen TEXT
)