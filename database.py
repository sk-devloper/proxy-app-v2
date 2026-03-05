"""
Non-blocking SQLite logger for J.A.R.V.I.S.
All writes run in a thread-pool executor so they never block the event loop.
WAL journal mode keeps reads fast while writes are in flight.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import config
from models import ConnectionMetrics, SecurityThreat


# ── error classifier ──────────────────────────────────────────────────────────

def classify_error(error: Optional[str]) -> Optional[str]:
    if not error:
        return None
    e = error.lower()
    if "timeout" in e or "timed out" in e:          return "TIMEOUT"
    if "dns" in e or "resolve" in e or "name or service" in e:
                                                    return "DNS_ERROR"
    if "refused" in e:                              return "CONN_REFUSED"
    if "reset" in e or "broken pipe" in e:          return "CONN_RESET"
    if "ssl" in e or "certificate" in e:            return "SSL_ERROR"
    if "malicious" in e:                            return "BLOCKED_MALICIOUS"
    if "whitelist" in e:                            return "BLOCKED_WHITELIST"
    if "rate limit" in e:                           return "RATE_LIMITED"
    if "blocked" in e:                              return "BLOCKED"
    if "header" in e or "bad request" in e:         return "BAD_REQUEST"
    if "cancelled" in e:                            return "CANCELLED"
    return "OTHER"


# ── database ──────────────────────────────────────────────────────────────────

class DatabaseLogger:
    """Async-safe SQLite logger — all I/O runs in a thread executor."""

    def __init__(self):
        db_path = config.get("database", "path", "logs/jarvis.db")
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── schema ────────────────────────────────────────────────────────────────

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            # Performance-tuned PRAGMA settings
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")

            # Step 1 — create tables (safe to run on existing DBs)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp        TEXT    NOT NULL,
                    type             TEXT,
                    client_ip        TEXT,
                    method           TEXT,
                    host             TEXT,
                    port             INTEGER,
                    url              TEXT,
                    status_code      INTEGER,
                    response_time_ms REAL,
                    dns_time_ms      REAL,
                    tcp_connect_ms   REAL,
                    body_bytes       INTEGER,
                    user_agent       TEXT,
                    security_level   TEXT,
                    cached           INTEGER,
                    compressed       INTEGER,
                    is_https         INTEGER,
                    country          TEXT,
                    city             TEXT,
                    isp              TEXT,
                    content_type     TEXT,
                    error            TEXT,
                    error_type       TEXT
                );
                CREATE TABLE IF NOT EXISTS threats (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip        TEXT,
                    host      TEXT,
                    level     TEXT,
                    reason    TEXT,
                    patterns  TEXT
                );
                CREATE TABLE IF NOT EXISTS connections (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT,
                    client_ip     TEXT,
                    host          TEXT,
                    port          INTEGER,
                    duration_ms   REAL,
                    bytes_sent    INTEGER,
                    bytes_recv    INTEGER,
                    error         TEXT,
                    error_type    TEXT
                );
                CREATE TABLE IF NOT EXISTS perf_snapshots (
                    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp               TEXT,
                    total_requests          INTEGER,
                    requests_this_minute    INTEGER,
                    active_connections      INTEGER,
                    avg_response_ms         REAL,
                    cache_hit_rate          REAL,
                    bytes_per_sec           REAL,
                    error_rate              REAL,
                    unique_clients          INTEGER,
                    threats_blocked         INTEGER
                );
            """)

            # Step 2 — migrate existing `requests` table (add columns that may be absent)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(requests)")}
            migrations = [
                ("type",             "ALTER TABLE requests ADD COLUMN type TEXT"),
                ("port",             "ALTER TABLE requests ADD COLUMN port INTEGER"),
                ("dns_time_ms",      "ALTER TABLE requests ADD COLUMN dns_time_ms REAL"),
                ("tcp_connect_ms",   "ALTER TABLE requests ADD COLUMN tcp_connect_ms REAL"),
                ("compressed",       "ALTER TABLE requests ADD COLUMN compressed INTEGER"),
                ("country",          "ALTER TABLE requests ADD COLUMN country TEXT"),
                ("city",             "ALTER TABLE requests ADD COLUMN city TEXT"),
                ("isp",              "ALTER TABLE requests ADD COLUMN isp TEXT"),
                ("content_type",     "ALTER TABLE requests ADD COLUMN content_type TEXT"),
                ("error_type",       "ALTER TABLE requests ADD COLUMN error_type TEXT"),
            ]
            for col, sql in migrations:
                if col not in existing:
                    conn.execute(sql)

            # Step 3 — create indexes (only after migrations so new columns exist)
            conn.executescript("""
                CREATE INDEX IF NOT EXISTS idx_req_ts       ON requests(timestamp);
                CREATE INDEX IF NOT EXISTS idx_req_host     ON requests(host);
                CREATE INDEX IF NOT EXISTS idx_req_client   ON requests(client_ip);
                CREATE INDEX IF NOT EXISTS idx_req_security ON requests(security_level);
                CREATE INDEX IF NOT EXISTS idx_req_error    ON requests(error_type);
                CREATE INDEX IF NOT EXISTS idx_thr_ts       ON threats(timestamp);
                CREATE INDEX IF NOT EXISTS idx_conn_ts      ON connections(timestamp);
                CREATE INDEX IF NOT EXISTS idx_perf_ts      ON perf_snapshots(timestamp);
            """)

            conn.commit()
        finally:
            conn.close()

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _in_executor(fn):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ── public API ────────────────────────────────────────────────────────────

    async def log_request(self, metrics: ConnectionMetrics):
        def _write():
            try:
                geo = metrics.geo_location
                ct  = metrics.content_type.value if metrics.content_type else None
                dns_ms = metrics.dns.dns_time_ms if metrics.dns else None
                conn = self._connect()
                conn.execute("""
                    INSERT INTO requests (
                        timestamp, type, client_ip, method, host, port, url,
                        status_code, response_time_ms, dns_time_ms, tcp_connect_ms,
                        body_bytes, user_agent, security_level, cached, compressed,
                        is_https, country, city, isp, content_type, error, error_type
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    metrics.timestamp, metrics.type, metrics.client_ip,
                    metrics.method, metrics.host, metrics.port, metrics.url,
                    metrics.status_code, metrics.response_time_ms, dns_ms,
                    metrics.tcp_connect_ms, metrics.body_bytes, metrics.user_agent,
                    metrics.security_level.value, int(metrics.cached),
                    int(metrics.compressed), int(metrics.is_https),
                    geo.country if geo else None,
                    geo.city    if geo else None,
                    geo.isp     if geo else None,
                    ct, metrics.error, classify_error(metrics.error),
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logging.error(f"DB log_request: {e}")
        await self._in_executor(_write)

    async def log_threat(self, threat: SecurityThreat):
        def _write():
            try:
                conn = self._connect()
                conn.execute("""
                    INSERT INTO threats (timestamp, ip, host, level, reason, patterns)
                    VALUES (?,?,?,?,?,?)
                """, (
                    threat.timestamp, threat.ip, threat.host,
                    threat.level.value, threat.reason, json.dumps(threat.patterns),
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logging.error(f"DB log_threat: {e}")
        await self._in_executor(_write)

    async def log_connection(
        self,
        client_ip: str,
        host: str,
        port: int,
        duration_ms: float,
        bytes_sent: int,
        bytes_recv: int,
        error: Optional[str] = None,
    ):
        def _write():
            try:
                conn = self._connect()
                conn.execute("""
                    INSERT INTO connections
                        (timestamp, client_ip, host, port,
                         duration_ms, bytes_sent, bytes_recv, error, error_type)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    datetime.utcnow().isoformat(),
                    client_ip, host, port, duration_ms,
                    bytes_sent, bytes_recv, error, classify_error(error),
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logging.error(f"DB log_connection: {e}")
        await self._in_executor(_write)

    async def log_perf_snapshot(
        self,
        total_requests: int = 0,
        requests_this_minute: int = 0,
        active_connections: int = 0,
        avg_response_ms: float = 0,
        cache_hit_rate: float = 0,
        bytes_per_sec: float = 0,
        error_rate: float = 0,
        unique_clients: int = 0,
        threats_blocked: int = 0,
    ):
        def _write():
            try:
                conn = self._connect()
                conn.execute("""
                    INSERT INTO perf_snapshots (
                        timestamp, total_requests, requests_this_minute,
                        active_connections, avg_response_ms, cache_hit_rate,
                        bytes_per_sec, error_rate, unique_clients, threats_blocked
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (
                    datetime.utcnow().isoformat(), total_requests,
                    requests_this_minute, active_connections, avg_response_ms,
                    cache_hit_rate, bytes_per_sec, error_rate,
                    unique_clients, threats_blocked,
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logging.error(f"DB log_perf_snapshot: {e}")
        await self._in_executor(_write)

    async def query(self, sql: str, params: tuple = ()) -> List[dict]:
        """Execute a SELECT and return list of dicts (safe for TUI DB pane)."""
        def _query():
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
            conn.close()
            return rows
        return await self._in_executor(_query)
