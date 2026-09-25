"""
drop_watch.config
=================
Load and validate configuration from config.local.json (or config.example.json as fallback).

Design note: All target IPs, hostnames, and SSIDs live ONLY in the user-edited config
file. The example file uses generic placeholders. The .local file is gitignored.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


DEFAULTS: Dict[str, Any] = {
    "targets": {
        "router_ip": "192.168.1.1",
        "internet_ips": ["8.8.8.8", "1.1.1.1"],
        "dns_resolvers": ["1.1.1.1", "8.8.8.8"],
        "dns_names": ["google.com", "cloudflare.com"],
        "http_probe_url": "https://httpbin.org/status/200",
        "vpn_probe": None,
    },
    "intervals_seconds": {
        "icmp_router": 1,
        "icmp_internet": 1,
        "dns": 5,
        "http": 10,
        "wifi": 5,
        "nic_stats": 30,
        "vpn": 10,
    },
    "thresholds": {
        "icmp_loss_consecutive_to_flag_drop": 3,
        "icmp_latency_ms_to_flag_spike": 200,
        "dns_latency_ms_to_flag_slow": 500,
        "dns_latency_ms_to_flag_drop": 1500,
        "http_latency_ms_to_flag_slow": 1500,
        "http_latency_ms_to_flag_drop": 3000,
    },
    "retention": {
        "raw_seconds": 86400,
        "rollup_5s_days": 7,
        "rollup_1m_days": 30,
    },
    "output": {
        "db_path": "drop_watch.db",
        "log_dir": "logs",
        "report_dir": "reports",
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override into base (override wins)."""
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | os.PathLike | None = None) -> Dict[str, Any]:
    """Load config from `path`, falling back to config.local.json / config.example.json.

    Resolution order:
      1. explicit `path` argument
      2. ./config.local.json
      3. ./config.json
      4. ./config.example.json
      5. built-in DEFAULTS
    """
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    candidates.extend([
        Path("config.local.json"),
        Path("config.json"),
        Path("config.example.json"),
    ])

    merged = dict(DEFAULTS)
    for c in candidates:
        if c.is_file():
            try:
                with c.open("r", encoding="utf-8") as f:
                    user = json.load(f)
                merged = _deep_merge(merged, user)
                # Strip comment keys (anything starting with underscore)
                merged = _strip_comments(merged)
                return merged
            except (OSError, json.JSONDecodeError) as e:
                print(f"[config] WARN failed to load {c}: {e}")
    return merged


def _strip_comments(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_comments(v) for v in obj]
    return obj
