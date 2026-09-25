"""
drop_watch.storage
==================
SQLite-backed sample storage with retention-driven downsampling.

Schema:
- samples: raw, one row per probe (ICMP, DNS, HTTP, NIC stats, Wi-Fi)
- drop_events: detected anomalies (loss burst, latency spike, BSSID change, etc.)

Design choices:
- timestamps stored as ISO-8601 UTC strings for human-readability
- sample_type + target together index samples
- drop_events link back to the trigger window via start_ts / end_ts
- rollup() averages across short windows so 24h of 1Hz probes stays small
"""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                  -- ISO-8601 UTC, ms precision
    sample_type TEXT NOT NULL,         -- icmp_router, icmp_internet, dns, http, wifi, nic, vpn
    target TEXT,                       -- IP, hostname, or SSID
    success INTEGER NOT NULL,          -- 0/1
    latency_ms REAL,                   -- nullable
    detail TEXT                        -- JSON for richer fields (signal, BSSID, errors, ...)
);
CREATE INDEX IF NOT EXISTS idx_samples_ts_type ON samples(ts, sample_type);
CREATE INDEX IF NOT EXISTS idx_samples_target ON samples(target);

CREATE TABLE IF NOT EXISTS drop_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts TEXT NOT NULL,
    end_ts TEXT NOT NULL,
    severity TEXT NOT NULL,            -- info, warn, drop
    sample_type TEXT NOT NULL,
    target TEXT,
    reason TEXT NOT NULL,
    metric_value REAL,                 -- e.g. peak latency
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_start ON drop_events(start_ts);

CREATE TABLE IF NOT EXISTS rollup_5s (
    ts TEXT NOT NULL,
    sample_type TEXT NOT NULL,
    target TEXT NOT NULL,
    count INTEGER NOT NULL,
    successes INTEGER NOT NULL,
    avg_latency_ms REAL,
    max_latency_ms REAL,
    PRIMARY KEY (ts, sample_type, target)
);
"""


class Store:
    """Thread-safe SQLite store. One writer at a time, many readers."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ inserts
    def add_sample(
        self,
        sample_type: str,
        target: str | None,
        success: bool,
        latency_ms: float | None,
        detail: dict | None = None,
        ts: datetime | None = None,
    ) -> None:
        ts = ts or datetime.now(timezone.utc)
        ts_str = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        detail_json = _json_or_none(detail)
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO samples (ts, sample_type, target, success, latency_ms, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ts_str, sample_type, target, 1 if success else 0, latency_ms, detail_json),
            )

    def add_drop_event(
        self,
        start_ts: datetime,
        end_ts: datetime,
        severity: str,
        sample_type: str,
        target: str | None,
        reason: str,
        metric_value: float | None = None,
        detail: dict | None = None,
    ) -> int:
        s = start_ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        e = end_ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        detail_json = _json_or_none(detail)
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO drop_events "
                "(start_ts, end_ts, severity, sample_type, target, reason, metric_value, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (s, e, severity, sample_type, target, reason, metric_value, detail_json),
            )
            return cur.lastrowid or 0

    # ------------------------------------------------------------------ queries
    def query_samples(
        self,
        since: datetime,
        until: datetime | None = None,
        sample_type: str | None = None,
        target: str | None = None,
        limit: int = 10000,
    ) -> list[dict]:
        until = until or datetime.now(timezone.utc)
        s = since.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        u = until.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        sql = (
            "SELECT ts, sample_type, target, success, latency_ms, detail "
            "FROM samples WHERE ts >= ? AND ts <= ?"
        )
        params: list[Any] = [s, u]
        if sample_type:
            sql += " AND sample_type = ?"
            params.append(sample_type)
        if target:
            sql += " AND target = ?"
            params.append(target)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "ts": r[0],
                "sample_type": r[1],
                "target": r[2],
                "success": bool(r[3]),
                "latency_ms": r[4],
                "detail": r[5],
            }
            for r in rows
        ]

    def query_events(
        self,
        since: datetime,
        until: datetime | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> list[dict]:
        until = until or datetime.now(timezone.utc)
        s = since.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        u = until.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        sql = "SELECT start_ts, end_ts, severity, sample_type, target, reason, metric_value FROM drop_events WHERE start_ts >= ? AND start_ts <= ?"
        params: list[Any] = [s, u]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY start_ts DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "start_ts": r[0],
                "end_ts": r[1],
                "severity": r[2],
                "sample_type": r[3],
                "target": r[4],
                "reason": r[5],
                "metric_value": r[6],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------ retention
    def prune(self, raw_seconds: int, rollup_5s_days: int, rollup_1m_days: int) -> dict:
        """Downsample then delete. Returns counts."""
        now = datetime.now(timezone.utc)
        cutoff_raw = (now - timedelta(seconds=raw_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        cutoff_5s = (now - timedelta(days=rollup_5s_days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        cutoff_1m = (now - timedelta(days=rollup_1m_days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        with self._lock, self._conn() as conn:
            # Build 5-second rollups from raw samples that are older than `raw_seconds`
            rollup_inserted = conn.execute(
                """
                INSERT OR REPLACE INTO rollup_5s (ts, sample_type, target, count, successes, avg_latency_ms, max_latency_ms)
                SELECT
                    strftime('%Y-%m-%dT%H:%M:%S', substr(ts, 1, 19) ||
                        CASE WHEN (CAST(strftime('%S', ts) AS INTEGER) / 5) * 5 < 10
                             THEN '0' || ((CAST(strftime('%S', ts) AS INTEGER) / 5) * 5)
                             ELSE ((CAST(strftime('%S', ts) AS INTEGER) / 5) * 5)
                        END) || 'Z' AS bucket,
                    sample_type,
                    COALESCE(target, '') AS target,
                    COUNT(*),
                    SUM(success),
                    AVG(latency_ms),
                    MAX(latency_ms)
                FROM samples
                WHERE ts < ?
                GROUP BY bucket, sample_type, target
                """,
                (cutoff_raw,),
            ).rowcount

            deleted_raw = conn.execute(
                "DELETE FROM samples WHERE ts < ?", (cutoff_raw,)
            ).rowcount
            deleted_5s = conn.execute(
                "DELETE FROM rollup_5s WHERE ts < ?", (cutoff_5s,)
            ).rowcount
            deleted_events = conn.execute(
                "DELETE FROM drop_events WHERE end_ts < ?", (cutoff_1m,)
            ).rowcount
            conn.execute("VACUUM")
        return {
            "rollup_inserted": rollup_inserted,
            "deleted_raw": deleted_raw,
            "deleted_5s": deleted_5s,
            "deleted_events": deleted_events,
        }


def _json_or_none(d: dict | None) -> str | None:
    if d is None:
        return None
    import json
    return json.dumps(d, default=str)
