"""
drop_watch.samplers
===================
Probe implementations. Each Sampler.run() is intended to be called on its own
thread via threading.Thread. They handle their own backoff and errors so a
single broken probe doesn't take down the rest.

Design: every probe returns a `Sample` dataclass rather than writing to the
store directly. The runner decides when to persist. This makes probes testable
and keeps I/O at the edges.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


# Windows subprocess flag to suppress a console flash.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


@dataclass
class Sample:
    ts: str
    sample_type: str
    target: str | None
    success: bool
    latency_ms: float | None
    detail: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------- ICMP
_PING_RE = re.compile(r"time[<=]([0-9]+)ms", re.IGNORECASE)
_PING_LOSS_RE = re.compile(r"\((\d+)%\s*loss\)", re.IGNORECASE)


def ping(host: str, timeout_ms: int = 1000) -> Sample:
    """Single-ping probe. latency_ms=None on failure."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        # Windows: -n 1 = count 1, -w N = timeout in ms
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout_ms)), host],
            capture_output=True,
            text=True,
            timeout=max(2.0, timeout_ms / 1000.0 + 1.0),
            creationflags=_NO_WINDOW,
        )
        out = result.stdout or ""
        m = _PING_RE.search(out)
        if m:
            return Sample(ts=ts, sample_type="icmp", target=host, success=True,
                          latency_ms=float(m.group(1)), detail={"raw": out[-300:]})
        return Sample(ts=ts, sample_type="icmp", target=host, success=False,
                      latency_ms=None, detail={"raw": out[-300:], "stderr": (result.stderr or "")[-200:]})
    except subprocess.TimeoutExpired:
        return Sample(ts=ts, sample_type="icmp", target=host, success=False,
                      latency_ms=None, detail={"reason": "timeout"})
    except Exception as e:
        return Sample(ts=ts, sample_type="icmp", target=host, success=False,
                      latency_ms=None, detail={"error": str(e)[:200]})


# ---------------------------------------------------------------------- DNS
def dns_lookup(name: str, resolver: str | None = None, timeout_s: float = 2.0) -> Sample:
    """Time a DNS lookup. resolver is advisory only (Windows resolver API doesn't take a server)."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    socket.setdefaulttimeout(timeout_s)
    t0 = time.perf_counter()
    try:
        addr = socket.gethostbyname(name)
        dt = (time.perf_counter() - t0) * 1000.0
        return Sample(ts=ts, sample_type="dns", target=name, success=True,
                      latency_ms=dt, detail={"resolved_to": addr, "resolver": resolver})
    except socket.gaierror as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return Sample(ts=ts, sample_type="dns", target=name, success=False,
                      latency_ms=dt, detail={"errno": e.errno, "strerror": e.strerror, "resolver": resolver})
    except Exception as e:
        return Sample(ts=ts, sample_type="dns", target=name, success=False,
                      latency_ms=None, detail={"error": str(e)[:200], "resolver": resolver})


# ---------------------------------------------------------------------- HTTP
def http_probe(url: str, timeout_s: float = 5.0) -> Sample:
    """Fetch a URL via stdlib urllib (no extra deps). Times the full round-trip."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "drop-watch/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = resp.status
            # Drain to measure full response
            _ = resp.read(64)
        dt = (time.perf_counter() - t0) * 1000.0
        return Sample(ts=ts, sample_type="http", target=url, success=200 <= status < 400,
                      latency_ms=dt, detail={"status": status})
    except urllib.error.HTTPError as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return Sample(ts=ts, sample_type="http", target=url, success=False,
                      latency_ms=dt, detail={"status": e.code, "reason": "http_error"})
    except urllib.error.URLError as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return Sample(ts=ts, sample_type="http", target=url, success=False,
                      latency_ms=dt, detail={"reason": "url_error", "detail": str(e.reason)[:200]})
    except Exception as e:
        return Sample(ts=ts, sample_type="http", target=url, success=False,
                      latency_ms=None, detail={"error": str(e)[:200]})


# ---------------------------------------------------------------------- Wi-Fi
_WIFI_RE_SSID = re.compile(r"^\s*SSID\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_WIFI_RE_BSSID = re.compile(r"^\s*BSSID\s*:\s*([0-9a-f:]+)\s*$", re.IGNORECASE | re.MULTILINE)
_WIFI_RE_SIGNAL = re.compile(r"^\s*Signal\s*:\s*(\d+)%\s*$", re.IGNORECASE | re.MULTILINE)
_WIFI_RE_STATE = re.compile(r"^\s*State\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_WIFI_RE_RADIO = re.compile(r"^\s*Radio\s*type\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_WIFI_RE_CHAN = re.compile(r"^\s*Channel\s*:\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def wifi_state() -> Sample:
    """Best-effort snapshot of Wi-Fi association via netsh. Returns success=False if disconnected."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=_NO_WINDOW,
        )
        out = result.stdout or ""
        ssid_m = _WIFI_RE_SSID.search(out)
        bssid_m = _WIFI_RE_BSSID.search(out)
        sig_m = _WIFI_RE_SIGNAL.search(out)
        state_m = _WIFI_RE_STATE.search(out)
        radio_m = _WIFI_RE_RADIO.search(out)
        chan_m = _WIFI_RE_CHAN.search(out)
        detail = {
            "ssid": (ssid_m.group(1).strip() if ssid_m else None),
            "bssid": (bssid_m.group(1).strip() if bssid_m else None),
            "signal_pct": (int(sig_m.group(1)) if sig_m else None),
            "state": (state_m.group(1).strip() if state_m else None),
            "radio": (radio_m.group(1).strip() if radio_m else None),
            "channel": (int(chan_m.group(1)) if chan_m else None),
        }
        connected = (detail["state"] or "").lower().startswith(("connected", "associating"))
        return Sample(ts=ts, sample_type="wifi", target=detail["ssid"], success=connected,
                      latency_ms=None, detail=detail)
    except subprocess.TimeoutExpired:
        return Sample(ts=ts, sample_type="wifi", target=None, success=False,
                      latency_ms=None, detail={"reason": "timeout"})
    except Exception as e:
        return Sample(ts=ts, sample_type="wifi", target=None, success=False,
                      latency_ms=None, detail={"error": str(e)[:200]})


# ---------------------------------------------------------------------- NIC stats
def nic_stats() -> list[Sample]:
    """Use netstat -e for cumulative bytes/errors/discards/unknown. Delta computation
    lives in monitor.py so we can derive throughput rates."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        result = subprocess.run(
            ["netstat", "-e"],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=_NO_WINDOW,
        )
        out = result.stdout or ""
        # Modern Windows prints just "Interface Statistics" with a columnar layout.
        # Older prints also include "IPv4 Statistics" / "IPv6 Statistics" blocks.
        # We try IPv4 first (more accurate on dual-stack), then fall back to
        # the Interface block.
        section_start = out.find("IPv4 Statistics")
        if section_start < 0:
            section_start = out.find("Interface Statistics")
        section = out[section_start:] if section_start >= 0 else out

        # Find the row labeled "Bytes" and parse the two integers on it.
        recv = sent = discards = errors = unknown = None
        for line in section.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            label = stripped.split()[0].lower()
            nums = [int(x) for x in stripped.split()[1:] if x.lstrip("-").isdigit()]
            if len(nums) < 2:
                continue
            if label == "bytes":
                recv, sent = nums[0], nums[1]
            elif label == "discards":
                discards, _ = nums[0], nums[1]
            elif label == "errors":
                errors, _ = nums[0], nums[1]
            elif label == "unknown":
                unknown = nums[0]
        detail = {
            "bytes_recv": recv, "bytes_sent": sent,
            "errors": errors, "discards": discards, "unknown": unknown,
        }
        return [Sample(ts=ts, sample_type="nic", target="ipv4_total",
                       success=recv is not None, latency_ms=None, detail=detail)]
    except Exception as e:
        return [Sample(ts=ts, sample_type="nic", target="ipv4_total",
                       success=False, latency_ms=None, detail={"error": str(e)[:200]})]
