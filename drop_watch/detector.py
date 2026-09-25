"""
drop_watch.detector
===================
Stateful drop detection. For each (sample_type, target) we keep a rolling
window and emit a DropEvent when thresholds cross.

Why stateful? A single dropped ping isn't a drop — three in a row is. A single
slow probe isn't a spike — a >5x jump from baseline is. We track both burst
loss and baseline drift.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque

from .samplers import Sample
from .storage import Store


@dataclass
class _State:
    last_results: Deque[bool] = field(default_factory=lambda: deque(maxlen=32))
    last_latencies: Deque[float] = field(default_factory=lambda: deque(maxlen=32))
    last_ssid: str | None = None
    last_bssid: str | None = None
    last_signal: int | None = None


class Detector:
    def __init__(self, store: Store, thresholds: dict):
        self.store = store
        self.thresholds = thresholds
        self._states: dict[tuple[str, str | None], _State] = {}

    def _state_for(self, sample_type: str, target: str | None) -> _State:
        key = (sample_type, target)
        if key not in self._states:
            self._states[key] = _State()
        return self._states[key]

    def observe(self, s: Sample) -> None:
        st = self._state_for(s.sample_type, s.target)
        st.last_results.append(s.success)
        if s.latency_ms is not None:
            st.last_latencies.append(s.latency_ms)

        now = datetime.now(timezone.utc)

        # ---- ICMP / TCP / DNS / HTTP — loss-burst detection
        if s.sample_type in ("icmp", "dns", "http", "vpn"):
            consec_loss = int(self._thresh("icmp_loss_consecutive_to_flag_drop", 3))
            if consec_loss < 1:
                consec_loss = 3
            recent = list(st.last_results)[-consec_loss:]
            if len(recent) >= consec_loss and all(not r for r in recent):
                # mark end as `now`, start as `consec_loss` seconds earlier (rough)
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="drop",
                    sample_type=s.sample_type, target=s.target,
                    reason=f"{consec_loss} consecutive failures",
                    metric_value=None,
                    detail={"last_detail": s.detail},
                )
                # clear so we don't spam
                st.last_results.clear()

        # ---- Latency spike (relative)
        if s.success and s.latency_ms is not None and len(st.last_latencies) >= 10:
            baseline = sum(list(st.last_latencies)[:-1]) / max(1, len(st.last_latencies) - 1)
            spike_thresh = self._thresh("icmp_latency_ms_to_flag_spike", 200)
            if baseline > 0 and s.latency_ms >= max(spike_thresh, baseline * 5):
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="warn",
                    sample_type=s.sample_type, target=s.target,
                    reason=f"latency spike {s.latency_ms:.0f}ms vs baseline {baseline:.0f}ms",
                    metric_value=s.latency_ms,
                    detail={"baseline_ms": baseline, "detail": s.detail},
                )

        # ---- DNS-specific slow threshold
        if s.sample_type == "dns" and s.success and s.latency_ms is not None:
            slow = self._thresh("dns_latency_ms_to_flag_slow", 500)
            drop_lvl = self._thresh("dns_latency_ms_to_flag_drop", 1500)
            if s.latency_ms >= drop_lvl:
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="drop",
                    sample_type="dns", target=s.target,
                    reason=f"DNS very slow: {s.latency_ms:.0f}ms",
                    metric_value=s.latency_ms,
                )
            elif s.latency_ms >= slow:
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="warn",
                    sample_type="dns", target=s.target,
                    reason=f"DNS slow: {s.latency_ms:.0f}ms",
                    metric_value=s.latency_ms,
                )

        # ---- HTTP-specific slow threshold
        if s.sample_type == "http" and s.success and s.latency_ms is not None:
            slow = self._thresh("http_latency_ms_to_flag_slow", 1500)
            drop_lvl = self._thresh("http_latency_ms_to_flag_drop", 3000)
            if s.latency_ms >= drop_lvl:
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="drop",
                    sample_type="http", target=s.target,
                    reason=f"HTTP very slow: {s.latency_ms:.0f}ms",
                    metric_value=s.latency_ms,
                )
            elif s.latency_ms >= slow:
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="warn",
                    sample_type="http", target=s.target,
                    reason=f"HTTP slow: {s.latency_ms:.0f}ms",
                    metric_value=s.latency_ms,
                )

        # ---- Wi-Fi: SSID/BSSID change = roaming or reconnect = drop
        if s.sample_type == "wifi":
            cur_ssid = s.detail.get("ssid")
            cur_bssid = s.detail.get("bssid")
            cur_signal = s.detail.get("signal_pct")
            if not s.success:
                self.store.add_drop_event(
                    start_ts=now, end_ts=now, severity="drop",
                    sample_type="wifi", target=cur_ssid,
                    reason=f"Wi-Fi disconnected (state={s.detail.get('state')})",
                    metric_value=cur_signal,
                    detail=s.detail,
                )
            else:
                if st.last_bssid and cur_bssid and st.last_bssid != cur_bssid:
                    self.store.add_drop_event(
                        start_ts=now, end_ts=now, severity="warn",
                        sample_type="wifi", target=cur_ssid,
                        reason=f"Wi-Fi BSSID change {st.last_bssid} -> {cur_bssid} (roam)",
                        metric_value=cur_signal,
                        detail={"old_bssid": st.last_bssid, "new_bssid": cur_bssid},
                    )
                if st.last_signal is not None and cur_signal is not None:
                    drop = st.last_signal - cur_signal
                    if drop >= 30:
                        self.store.add_drop_event(
                            start_ts=now, end_ts=now, severity="warn",
                            sample_type="wifi", target=cur_ssid,
                            reason=f"Wi-Fi signal drop {st.last_signal}% -> {cur_signal}%",
                            metric_value=cur_signal,
                        )
            st.last_ssid, st.last_bssid, st.last_signal = cur_ssid, cur_bssid, cur_signal

    def _thresh(self, key: str, default: float) -> float:
        try:
            return float(self.thresholds.get(key, default))
        except (TypeError, ValueError):
            return float(default)
