"""
drop_watch.notify
=================
Email notification hook. Reads SMTP/AgentMail config from environment
variables so we never put credentials in the config file or git.

Supported backends:
- agentmail (default): REST POST to api.agentmail.to
- smtp: standard smtplib SMTP+STARTTLS

Env vars:
- AGENTMAIL_API_KEY, AGENTMAIL_INBOX, AGENTMAIL_DISPLAY_NAME (agentmail mode)
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM (smtp mode)
- NOTIFY_TO (recipient address; required)
- NOTIFY_BACKEND (optional; auto-detected)
- NOTIFY_COOLDOWN_SECONDS (optional; default 30 — prevents email floods
  when a flapping link produces 10+ drop events per minute)
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable

log = logging.getLogger("drop_watch.notify")


def _load_dotenv(path: str | Path | None = None) -> None:
    """Light .env loader. Only sets vars that are not already in os.environ."""
    path = Path(path) if path else Path.home() / "drop-watch" / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        os.environ.setdefault(k, v)


@dataclass
class _DedupKey:
    sample_type: str
    target: str | None
    severity: str


class Notifier:
    """Send email on drop events. Cooldown-debounced."""

    def __init__(self, to: str | None = None, backend: str | None = None,
                 cooldown_seconds: float = 30.0):
        _load_dotenv()
        self.to = to or os.environ.get("NOTIFY_TO")
        if not self.to:
            raise RuntimeError("NOTIFY_TO not set in env or .env")
        self.backend = (backend or os.environ.get("NOTIFY_BACKEND") or "auto").lower()
        self.cooldown_seconds = float(os.environ.get("NOTIFY_COOLDOWN_SECONDS", cooldown_seconds))
        self._last_sent: dict[tuple, float] = {}

    # ------------------------------------------------------------------ public
    def send_drop(self, event: dict, recent_context: Iterable[dict] | None = None) -> bool:
        """Send an email for a drop event. Returns True if sent, False if debounced or failed."""
        key = (event.get("sample_type", ""), event.get("target") or "", event.get("severity", ""))
        now = time.monotonic()
        last = self._last_sent.get(key, 0.0)
        if now - last < self.cooldown_seconds:
            log.debug("[notify] debounced %s (%.1fs since last)", key, now - last)
            return False
        subject = self._subject(event)
        body = self._body(event, recent_context)
        ok = self._dispatch(subject, body)
        if ok:
            self._last_sent[key] = now
        return ok

    # ------------------------------------------------------------------ formatting
    @staticmethod
    def _subject(e: dict) -> str:
        sev = e.get("severity", "drop").upper()
        st = e.get("sample_type", "?")
        tgt = e.get("target") or "—"
        reason = e.get("reason", "")
        return f"[drop-watch][{sev}] {st} {tgt} — {reason[:80]}"

    @staticmethod
    def _body(e: dict, ctx: Iterable[dict] | None) -> str:
        lines = [
            "drop-watch detected an event on box (192.168.1.164):",
            "",
            f"  Time      : {e.get('start_ts')}",
            f"  Severity  : {e.get('severity', '').upper()}",
            f"  Probe     : {e.get('sample_type')}",
            f"  Target    : {e.get('target')}",
            f"  Reason    : {e.get('reason')}",
        ]
        if e.get("metric_value") is not None:
            lines.append(f"  Metric    : {e['metric_value']:.1f}")
        if ctx:
            lines.append("")
            lines.append("Recent samples (last ~5):")
            for c in list(ctx)[-5:]:
                lines.append(f"  - {c.get('ts')}  {c.get('sample_type')}  {c.get('target')}  "
                             f"ok={c.get('success')}  lat={c.get('latency_ms')}")
        lines.append("")
        lines.append("Full data: drop_watch.db on box.")
        lines.append("Live report: python -m drop_watch report --hours 1")
        return "\n".join(lines)

    # ------------------------------------------------------------------ dispatch
    def _dispatch(self, subject: str, body: str) -> bool:
        backend = self.backend
        if backend == "auto":
            if os.environ.get("AGENTMAIL_API_KEY"):
                backend = "agentmail"
            elif os.environ.get("SMTP_HOST"):
                backend = "smtp"
            else:
                log.error("[notify] no backend env vars set; cannot send")
                return False
        try:
            if backend == "agentmail":
                return self._send_agentmail(subject, body)
            if backend == "smtp":
                return self._send_smtp(subject, body)
            log.error("[notify] unknown backend %r", backend)
            return False
        except Exception as e:
            log.exception("[notify] send failed: %s", e)
            return False

    def _send_agentmail(self, subject: str, body: str) -> bool:
        api_key = os.environ.get("AGENTMAIL_API_KEY")
        inbox = os.environ.get("AGENTMAIL_INBOX")
        display = os.environ.get("AGENTMAIL_DISPLAY_NAME", "drop-watch")
        if not api_key or not inbox:
            log.error("[notify] AGENTMAIL_API_KEY or AGENTMAIL_INBOX missing")
            return False
        payload = {
            "to": [self.to],
            "subject": subject,
            "text": body,
            "headers": {"From": f'"{display}" <{inbox}>'},
        }
        url = f"https://api.agentmail.to/v0/inboxes/{inbox}/messages/send"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    log.info("[notify] sent via agentmail: %s", subject)
                    return True
                log.error("[notify] agentmail HTTP %s: %s", resp.status, resp.read()[:300])
                return False
        except urllib.error.HTTPError as e:
            log.error("[notify] agentmail HTTPError %s: %s", e.code, e.read()[:300])
            return False

    def _send_smtp(self, subject: str, body: str) -> bool:
        host = os.environ["SMTP_HOST"]
        port = int(os.environ.get("SMTP_PORT", "587"))
        user = os.environ.get("SMTP_USER", "")
        password = os.environ.get("SMTP_PASSWORD", "")
        sender = os.environ["SMTP_FROM"]
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = self.to
        msg["Subject"] = subject
        msg.set_content(body)
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, password)
            s.send_message(msg)
        log.info("[notify] sent via smtp: %s", subject)
        return True
