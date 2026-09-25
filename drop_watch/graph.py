"""
drop_watch.graph
================
Generate a multi-panel time-series PNG of recent samples.

Layout:
  Panel 1 — Router latency (ms) over time, with loss markers
  Panel 2 — Internet latency (one line per target)
  Panel 3 — DNS latency
  Panel 4 — HTTP latency
  Panel 5 — NIC throughput (Mbps up + down)

This is intentionally separate from monitor.py so matplotlib isn't a hard
runtime dependency of the monitor itself.
"""
from __future__ import annotations

import argparse
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def _load_series(db_path: str, since: datetime, until: datetime):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    s = since.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    u = until.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    cur.execute(
        "SELECT ts, sample_type, target, success, latency_ms, detail "
        "FROM samples WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
        (s, u),
    )
    rows = cur.fetchall()
    conn.close()
    series = defaultdict(list)  # key: (sample_type, target) -> list of (datetime, latency_ms, success, detail)
    for r in rows:
        ts = datetime.fromisoformat(r[0].replace("Z", "+00:00"))
        series[(r[1], r[2])].append((ts, r[4], bool(r[3]), r[5]))
    return series


def render(db_path: str, hours: int, output: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    series = _load_series(db_path, since, now)
    if not series:
        print("No data in window. Run the monitor first.")
        return

    panels = [
        ("icmp", "ICMP (ms)"),
        ("dns", "DNS (ms)"),
        ("http", "HTTP (ms)"),
        ("nic", "NIC throughput (Mbps)"),
    ]
    fig, axes = plt.subplots(len(panels), 1, figsize=(12, 10), sharex=True)
    if len(panels) == 1:
        axes = [axes]
    colors = ["tab:blue", "tab:orange", "tab:green", "tab:red", "tab:purple", "tab:brown"]

    for ax, (sample_type, ylabel) in zip(axes, panels):
        for idx, ((st, target), pts) in enumerate(sorted(series.items())):
            if st != sample_type:
                continue
            xs = [p[0] for p in pts]
            ys = []
            for p in pts:
                if sample_type == "nic":
                    d = p[3] or {}
                    ys.append(d.get("mbps_recv") or 0)
                else:
                    ys.append(p[1] if (p[1] is not None and p[2]) else None)
            ax.plot(xs, ys, label=target or st, color=colors[idx % len(colors)], linewidth=1.0)
            # mark failures
            fail_x = [p[0] for p in pts if not p[2]]
            fail_y = [0] * len(fail_x)
            if fail_x:
                ax.scatter(fail_x, fail_y, marker="x", color="red", s=20, alpha=0.6, label="_nolegend_")
        ax.set_ylabel(ylabel)
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.legend(loc="upper right", fontsize=8)

    axes[-1].xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate()
    fig.suptitle(f"drop-watch — last {hours}h", fontsize=14)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    print(f"Wrote {output}")


def main():
    ap = argparse.ArgumentParser(description="Render drop-watch samples as a multi-panel PNG")
    ap.add_argument("--db", default="drop_watch.db")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--output", default=None,
                    help="output PNG path (default: drop_watch_graph-<timestamp>.png)")
    args = ap.parse_args()
    out = args.output or f"drop_watch_graph-{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
    render(args.db, args.hours, out)


if __name__ == "__main__":
    main()
