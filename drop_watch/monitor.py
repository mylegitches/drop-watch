"""
drop_watch.monitor
==================
The orchestrator. Spawns a thread per probe type, each on its own cadence,
feeds samples into Store + Detector.

To keep the process well-behaved on a laptop that may sleep/resume:
- daemon threads (don't block shutdown)
- a heartbeat log every 60s
- a retention pruner every hour
- a clean shutdown on SIGINT/SIGTERM
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from datetime import datetime, timezone

from .config import load_config
from .detector import Detector
from .samplers import Sample, ping, dns_lookup, http_probe, wifi_state, nic_stats
from .storage import Store


log = logging.getLogger("drop_watch")


class Monitor:
    def __init__(self, config: dict | None = None):
        self.config = config or load_config()
        self.store = Store(self.config["output"]["db_path"])
        self.detector = Detector(self.store, self.config.get("thresholds", {}))
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_nic: tuple[int | None, int | None, int | None, int | None, float] | None = None

    # ------------------------------------------------------------------ thread runners
    def _loop(self, name: str, interval_s: float, fn):
        """Generic probe loop. interval_s may be < 1 for sub-second cadence."""
        next_at = time.monotonic()
        while not self._stop.is_set():
            now_m = time.monotonic()
            if now_m < next_at:
                self._stop.wait(min(0.5, next_at - now_m))
                continue
            t0 = time.monotonic()
            try:
                result = fn()
                if isinstance(result, list):
                    for r in result:
                        self._handle(r)
                else:
                    self._handle(result)
            except Exception as e:
                log.exception("[%s] probe failed: %s", name, e)
            # Drift-corrected next tick
            next_at = max(next_at + interval_s, time.monotonic())

    def _loop_icmp_router(self):
        host = self.config["targets"]["router_ip"]
        i = self.config["intervals_seconds"]["icmp_router"]
        self._loop("icmp_router", i, lambda: ping(host))

    def _loop_icmp_internet(self):
        ips = self.config["targets"]["internet_ips"]
        i = self.config["intervals_seconds"]["icmp_internet"]
        # Round-robin through the IPs at this cadence
        idx = {"i": 0}
        def tick():
            ip = ips[idx["i"] % len(ips)]
            idx["i"] += 1
            return ping(ip)
        self._loop("icmp_internet", i, tick)

    def _loop_dns(self):
        names = self.config["targets"]["dns_names"]
        resolvers = self.config["targets"]["dns_resolvers"]
        i = self.config["intervals_seconds"]["dns"]
        idx = {"i": 0}
        def tick():
            name = names[idx["i"] % len(names)]
            res = resolvers[idx["i"] % len(resolvers)]
            idx["i"] += 1
            return dns_lookup(name, resolver=res)
        self._loop("dns", i, tick)

    def _loop_http(self):
        url = self.config["targets"]["http_probe_url"]
        i = self.config["intervals_seconds"]["http"]
        self._loop("http", i, lambda: http_probe(url))

    def _loop_vpn(self):
        vpn = self.config["targets"].get("vpn_probe")
        if not vpn:
            # sleep until shutdown to avoid pointless work
            while not self._stop.is_set():
                self._stop.wait(60)
            return
        i = self.config["intervals_seconds"]["vpn"]
        self._loop("vpn", i, lambda: tcp_probe(vpn["host"], vpn["port"]))

    def _loop_wifi(self):
        i = self.config["intervals_seconds"]["wifi"]
        self._loop("wifi", i, wifi_state)

    def _loop_nic(self):
        i = self.config["intervals_seconds"]["nic_stats"]
        # Custom loop because NIC stats need delta computation
        next_at = time.monotonic()
        while not self._stop.is_set():
            now_m = time.monotonic()
            if now_m < next_at:
                self._stop.wait(min(0.5, next_at - now_m))
                continue
            try:
                samples = nic_stats()
                if samples:
                    s = samples[0]
                    cur = (
                        s.detail.get("bytes_recv"),
                        s.detail.get("bytes_sent"),
                        s.detail.get("errors"),
                        s.detail.get("discards"),
                        time.monotonic(),
                    )
                    if self._last_nic:
                        prev_r, prev_s, prev_e, prev_d, prev_t = self._last_nic
                        elapsed = max(0.001, cur[4] - prev_t)
                        if all(v is not None for v in (cur[0], cur[1], cur[2], cur[3], prev_r, prev_s)):
                            s.detail["mbps_recv"] = ((cur[0] - prev_r) * 8 / 1_000_000) / elapsed
                            s.detail["mbps_sent"] = ((cur[1] - prev_s) * 8 / 1_000_000) / elapsed
                            s.detail["errors_delta"] = (cur[2] or 0) - (prev_e or 0)
                            s.detail["discards_delta"] = (cur[3] or 0) - (prev_d or 0)
                            if s.detail["errors_delta"] > 0 or s.detail["discards_delta"] > 0:
                                self.detector.observe(s)  # trigger Wi-Fi-like spike handler
                    self._last_nic = cur
                    self.store.add_sample(
                        sample_type=s.sample_type, target=s.target,
                        success=s.success, latency_ms=s.latency_ms, detail=s.detail,
                    )
            except Exception as e:
                log.exception("[nic] probe failed: %s", e)
            next_at = max(next_at + i, time.monotonic())

    def _loop_heartbeat(self):
        """Periodically emit a heartbeat so the operator knows the monitor is alive."""
        while not self._stop.is_set():
            self._stop.wait(60)
            try:
                n_samples = self.store.query_samples(
                    since=datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0),
                    limit=1_000_000,
                )
                log.info("[heartbeat] alive; %d samples in last 24h window", len(n_samples))
            except Exception:
                log.exception("[heartbeat] failed")

    def _loop_retention(self):
        """Hourly retention prune."""
        while not self._stop.is_set():
            self._stop.wait(3600)
            try:
                ret = self.config.get("retention", {})
                res = self.store.prune(
                    raw_seconds=int(ret.get("raw_seconds", 86400)),
                    rollup_5s_days=int(ret.get("rollup_5s_days", 7)),
                    rollup_1m_days=int(ret.get("rollup_1m_days", 30)),
                )
                log.info("[retention] pruned: %s", res)
            except Exception:
                log.exception("[retention] failed")

    # ------------------------------------------------------------------ lifecycle
    def _handle(self, s: Sample):
        self.store.add_sample(
            sample_type=s.sample_type, target=s.target,
            success=s.success, latency_ms=s.latency_ms, detail=s.detail,
        )
        self.detector.observe(s)

    def start(self):
        log.info("drop-watch starting (PID %d)", __import__("os").getpid())
        self._threads = [
            threading.Thread(target=self._loop_icmp_router, name="icmp_router", daemon=True),
            threading.Thread(target=self._loop_icmp_internet, name="icmp_internet", daemon=True),
            threading.Thread(target=self._loop_dns, name="dns", daemon=True),
            threading.Thread(target=self._loop_http, name="http", daemon=True),
            threading.Thread(target=self._loop_vpn, name="vpn", daemon=True),
            threading.Thread(target=self._loop_wifi, name="wifi", daemon=True),
            threading.Thread(target=self._loop_nic, name="nic", daemon=True),
            threading.Thread(target=self._loop_heartbeat, name="heartbeat", daemon=True),
            threading.Thread(target=self._loop_retention, name="retention", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def stop(self):
        log.info("drop-watch stopping…")
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5.0)
        log.info("drop-watch stopped.")

    def wait_forever(self):
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.stop()


# ---------------------------------------------------------------------- TCP probe (for VPN)
def tcp_probe(host: str, port: int, timeout_s: float = 3.0):
    """Open a TCP connection and immediately close. Latency = connect time."""
    from datetime import datetime, timezone
    import socket
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            pass
        dt = (time.monotonic() - t0) * 1000.0
        return Sample(ts=ts, sample_type="vpn", target=f"{host}:{port}", success=True,
                      latency_ms=dt, detail={})
    except Exception as e:
        dt = (time.monotonic() - t0) * 1000.0
        return Sample(ts=ts, sample_type="vpn", target=f"{host}:{port}", success=False,
                      latency_ms=dt if dt < timeout_s * 1000 else None,
                      detail={"error": str(e)[:200]})


def install_signal_handlers(monitor: Monitor):
    def handler(signum, frame):
        log.info("signal %s received", signum)
        monitor.stop()
        import sys; sys.exit(0)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass  # not all signals are installable on Windows in some contexts
