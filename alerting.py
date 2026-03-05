"""Webhook alerting for J.A.R.V.I.S. Proxy.

Sends an async HTTP POST to a configured webhook URL when a threat
at or above the configured minimum level is detected.

Supports Discord, Slack, and any generic JSON webhook endpoint.
Retries with exponential backoff on transient failures.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

import aiohttp

from models import SecurityLevel, SecurityThreat

log = logging.getLogger("JARVIS.alerting")

# Severity ordering for threshold comparison
_LEVEL_ORDER = {
    SecurityLevel.SAFE: 0,
    SecurityLevel.SUSPICIOUS: 1,
    SecurityLevel.MALICIOUS: 2,
    SecurityLevel.BLOCKED: 3,
}

_LEVEL_EMOJI = {
    SecurityLevel.SUSPICIOUS: "⚠️",
    SecurityLevel.MALICIOUS: "🚨",
    SecurityLevel.BLOCKED: "🛑",
}


def _build_payload(threat: SecurityThreat, proxy_host: str = "") -> dict:
    """Build a generic JSON payload compatible with Discord/Slack/generic."""
    emoji = _LEVEL_EMOJI.get(threat.level, "ℹ️")
    title = f"{emoji} JARVIS Proxy — {threat.level.value.upper()}"
    text = (
        f"**Host:** `{threat.host}`\n"
        f"**Client:** `{threat.ip}`\n"
        f"**Reason:** {threat.reason}\n"
        f"**Time:** {threat.timestamp}"
    )
    # Discord-compatible embed
    discord_payload = {
        "embeds": [{
            "title": title,
            "description": text,
            "color": 0xFF0000 if threat.level == SecurityLevel.MALICIOUS else 0xFF8800,
            "timestamp": threat.timestamp,
        }]
    }
    return discord_payload


class WebhookAlerter:
    """Sends threat notifications to a webhook URL.

    Usage::

        alerter = WebhookAlerter(webhook_url="https://...", min_level=SecurityLevel.MALICIOUS)
        await alerter.send(threat)
    """

    def __init__(
        self,
        webhook_url: str,
        min_level: SecurityLevel = SecurityLevel.MALICIOUS,
        retry_count: int = 3,
        retry_delay: float = 2.0,
        proxy_host: str = "",
    ):
        self.webhook_url = webhook_url
        self.min_level = min_level
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.proxy_host = proxy_host
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._lock:
            if self._session is None or self._session.closed:
                self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        async with self._lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None

    def _should_alert(self, threat: SecurityThreat) -> bool:
        return _LEVEL_ORDER.get(threat.level, 0) >= _LEVEL_ORDER.get(self.min_level, 0)

    async def send(self, threat: SecurityThreat) -> None:
        """Send the threat notification. Silently drops if below min_level."""
        if not self.webhook_url or not self._should_alert(threat):
            return
        payload = _build_payload(threat, self.proxy_host)
        await self._send_with_retry(payload)

    async def _send_with_retry(self, payload: dict) -> None:
        session = await self._get_session()
        timeout = aiohttp.ClientTimeout(total=10)
        delay = self.retry_delay
        for attempt in range(1, self.retry_count + 1):
            try:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    if resp.status < 300:
                        log.debug(f"Webhook delivered (HTTP {resp.status})")
                        return
                    log.warning(
                        f"Webhook attempt {attempt}: HTTP {resp.status}"
                    )
            except Exception as exc:
                log.warning(f"Webhook attempt {attempt} failed: {exc}")
            if attempt < self.retry_count:
                await asyncio.sleep(delay)
                delay *= 2  # exponential backoff
        log.error("Webhook delivery failed after all retries")
