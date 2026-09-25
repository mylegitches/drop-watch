"""
drop_watch.cli
==============
Command-line entry point.

Usage:
  python -m drop_watch run [--config PATH] [--once]    # start the monitor
  python -m drop_watch report [--hours 24]              # print drop summary
  python -m drop_watch prune                           # run retention now
  python -m drop_watch doctor                          # check your config & system
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from .config import load_config
from .monitor import Monitor, install_signal_handlers
from .storage import Store


def cmd_run(args):
    cfg = load_config(getattr(args, "config", None) or getattr(args, "_config_path", None))
    if args.once:
        # One-shot probe of every type for a sanity check.
        from .samplers import ping, dns_lookup, http_probe, wifi_state, nic_stats
        print(json.dumps({
            "router": ping(cfg["targets"]["router_ip"]).__dict__,
            "internet": [ping(ip).__dict__ for ip in cfg["targets"]["internet_ips"]],
            "dns": [dns_lookup(n).__dict__ for n in cfg["targets"]["dns_names"]],
            "http": http_probe(cfg["targets"]["http_probe_url"]).__dict__,
            "wifi": wifi_state().__dict__,
            "nic": [s.__dict__ for s in nic_stats()],
        }, indent=2, default=str))
        return
    _setup_logging(cfg)
    mon = Monitor(cfg, enable_notifications=not getattr(args, "no_notify", False))
    install_signal_handlers(mon)
    mon.start()
    mon.wait_forever()


def _setup_logging(cfg: dict) -> None:
    """Send INFO+ from drop_watch.* to both stderr and a rotating log file
    (logs/drop_watch.log). File is appended to across restarts so the
    72-hour run produces a single contiguous log."""
    import logging
    from logging.handlers import RotatingFileHandler
    from pathlib import Path

    log_dir = Path(cfg.get("output", {}).get("log_dir", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "drop_watch.log"

    root = logging.getLogger("drop_watch")
    root.setLevel(logging.INFO)
    # Idempotent: clear existing handlers in case monitor.py was imported elsewhere
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)sZ %(name)s %(levelname)s %(message)s",
                            datefmt="%Y-%m-%dT%H:%M:%S")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    fh = RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(sh)
    root.addHandler(fh)
    logging.getLogger("drop_watch").info("[logging] writing to %s", log_file)


def cmd_report(args):
    cfg = load_config(getattr(args, "config", None) or getattr(args, "_config_path", None))
    store = Store(cfg["output"]["db_path"])
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    samples = store.query_samples(since=since, limit=1_000_000)
    events = store.query_events(since=since, limit=1_000_000)

    print(f"=== drop-watch report — last {args.hours}h ===")
    print(f"Total samples : {len(samples)}")
    print(f"Drop events   : {len(events)}")

    # Sample-type breakdown
    by_type: dict[str, dict] = {}
    for s in samples:
        st = s["sample_type"]
        d = by_type.setdefault(st, {"total": 0, "ok": 0, "lat_sum": 0.0, "lat_n": 0, "max_lat": 0.0})
        d["total"] += 1
        if s["success"]:
            d["ok"] += 1
        if s["latency_ms"] is not None:
            d["lat_sum"] += s["latency_ms"]
            d["lat_n"] += 1
            if s["latency_ms"] > d["max_lat"]:
                d["max_lat"] = s["latency_ms"]

    print("\nPer-probe summary:")
    for st, d in sorted(by_type.items()):
        loss_pct = 100.0 * (d["total"] - d["ok"]) / max(1, d["total"])
        avg = d["lat_sum"] / max(1, d["lat_n"])
        print(f"  {st:14s}  n={d['total']:>6}  loss={loss_pct:5.1f}%  avg={avg:6.1f}ms  max={d['max_lat']:7.1f}ms")

    # Recent drop events (most recent 30)
    if events:
        print(f"\nMost recent drop events (showing up to 30 of {len(events)}):")
        for e in events[:30]:
            ts = e["start_ts"]
            sev = e["severity"].upper()
            tgt = e.get("target") or "-"
            print(f"  [{ts}] {sev:4s} {e['sample_type']:8s} {tgt:30s}  {e['reason']}")
    else:
        print("\nNo drop events recorded in this window. "
              "If you suspect drops, check that thresholds aren't too lenient for your link.")


def cmd_prune(args):
    cfg = load_config(getattr(args, "config", None) or getattr(args, "_config_path", None))
    store = Store(cfg["output"]["db_path"])
    ret = cfg.get("retention", {})
    res = store.prune(
        raw_seconds=int(ret.get("raw_seconds", 86400)),
        rollup_5s_days=int(ret.get("rollup_5s_days", 7)),
        rollup_1m_days=int(ret.get("rollup_1m_days", 30)),
    )
    print(json.dumps(res, indent=2))


def cmd_doctor(args):
    """Quick environment sanity check: config loaded, can we reach each target."""
    cfg = load_config(getattr(args, "config", None) or getattr(args, "_config_path", None))
    from .samplers import ping, dns_lookup, http_probe
    print("=== drop-watch doctor ===")
    print(f"router_ip         : {cfg['targets']['router_ip']}")
    print(f"internet_ips      : {cfg['targets']['internet_ips']}")
    print(f"dns_names         : {cfg['targets']['dns_names']}")
    print(f"http_probe_url    : {cfg['targets']['http_probe_url']}")
    print(f"vpn_probe         : {cfg['targets'].get('vpn_probe')}")
    print()
    print("Pinging router…")
    print("  ", ping(cfg["targets"]["router_ip"]).__dict__)
    for ip in cfg["targets"]["internet_ips"]:
        print(f"Pinging {ip}…")
        print("  ", ping(ip).__dict__)
    for n in cfg["targets"]["dns_names"]:
        print(f"Resolving {n}…")
        print("  ", dns_lookup(n).__dict__)
    print("HTTP probe…")
    print("  ", http_probe(cfg["targets"]["http_probe_url"]).__dict__)


def main(argv=None):
    # Config flag is global; subcommand arguments follow.
    # Use: drop_watch --config foo.json run
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", help="path to config file")
    pre_args, rest = pre.parse_known_args(argv)

    p = argparse.ArgumentParser(prog="drop_watch", parents=[pre])
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="start the monitor", parents=[pre])
    pr.add_argument("--once", action="store_true", help="one-shot probe of every type and exit")
    pr.add_argument("--no-notify", action="store_true", help="disable email drop notifications")
    pr.set_defaults(func=cmd_run, _config=pre_args.config)

    pp = sub.add_parser("report", help="print a summary of recent samples and drop events", parents=[pre])
    pp.add_argument("--hours", type=int, default=24, help="window in hours (default 24)")
    pp.set_defaults(func=cmd_report, _config=pre_args.config)

    pp = sub.add_parser("prune", help="run retention pruning immediately", parents=[pre])
    pp.set_defaults(func=cmd_prune, _config=pre_args.config)

    pd = sub.add_parser("doctor", help="sanity check config + reach each target once", parents=[pre])
    pd.set_defaults(func=cmd_doctor, _config=pre_args.config)

    args = p.parse_args(rest)
    # Re-stitch config: prefer the per-subcommand value if user placed it after subcmd.
    cfg_path = getattr(args, "_config", None) or pre_args.config
    args._config_path = cfg_path
    args.func(args)


if __name__ == "__main__":
    main()
