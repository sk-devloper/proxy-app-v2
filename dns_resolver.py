"""DNS-over-HTTPS (DoH) resolver for J.A.R.V.I.S. Proxy.

Replaces or supplements the default system DNS resolution with encrypted
HTTPS queries to a configurable DoH provider.  Results are cached with
the TTL returned by the DoH server (or a configurable default).

Config section (config.yaml)::

    dns:
      doh_enabled: false
      doh_provider: "cloudflare"   # "cloudflare" | "google" | custom URL
      doh_timeout: 5.0
      cache_ttl: 300               # fallback TTL when server returns none
"""
from __future__ import annotations

import asyncio
import json
import ssl
import time
import urllib.request
from typing import Dict, List, Optional, Tuple


_PROVIDERS: Dict[str, str] = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/resolve",
}

_DEFAULT_TTL = 300  # seconds


class DoHResolver:
    """Async DNS-over-HTTPS resolver with in-memory TTL cache."""

    def __init__(
        self,
        provider: str = "cloudflare",
        timeout: float = 5.0,
        cache_ttl: int = _DEFAULT_TTL,
    ):
        url = _PROVIDERS.get(provider, provider)  # allow raw URL as provider
        self._url      = url
        self._timeout  = timeout
        self._cache_ttl = cache_ttl
        # cache: hostname → (addresses, expiry_monotonic)
        self._cache: Dict[str, Tuple[List[str], float]] = {}
        self._ssl_ctx = ssl.create_default_context()

    async def resolve(self, hostname: str) -> List[str]:
        """Return list of IP address strings for *hostname*.

        Uses cache first; falls back to system DNS if DoH fails.
        """
        # Cache hit
        if hostname in self._cache:
            addrs, expiry = self._cache[hostname]
            if time.monotonic() < expiry:
                return addrs

        try:
            addrs = await asyncio.wait_for(
                self._query(hostname), timeout=self._timeout
            )
        except Exception:
            # Graceful degradation: let the caller fall back to system DNS
            return []

        if addrs:
            self._cache[hostname] = (addrs, time.monotonic() + self._cache_ttl)
        return addrs

    async def _query(self, hostname: str) -> List[str]:
        """Fire the actual DoH JSON API request in a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_query, hostname)

    def _sync_query(self, hostname: str) -> List[str]:
        """Synchronous JSON-over-HTTPS query (runs in thread pool)."""
        url = f"{self._url}?name={hostname}&type=A"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
            data = json.loads(resp.read())

        addrs: List[str] = []
        for answer in data.get("Answer", []):
            # type 1 = A record, type 28 = AAAA
            if answer.get("type") in (1, 28):
                addrs.append(answer["data"])
        return addrs

    @classmethod
    def from_config(cls, config: dict) -> Optional["DoHResolver"]:
        """Return a DoHResolver if enabled in config, else None."""
        dns_cfg = config.get("dns", {})
        if not dns_cfg.get("doh_enabled", False):
            return None
        return cls(
            provider  = dns_cfg.get("doh_provider", "cloudflare"),
            timeout   = float(dns_cfg.get("doh_timeout", 5.0)),
            cache_ttl = int(dns_cfg.get("cache_ttl", _DEFAULT_TTL)),
        )
