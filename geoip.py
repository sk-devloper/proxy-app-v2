"""GeoIP resolver — uses ip-api.com (free, no key) with local private-IP fast-path."""
import asyncio
import ipaddress
import time
from typing import Dict, Optional

import aiohttp

import config
from models import GeoLocation


class GeoIPResolver:
    """Async GeoIP resolver backed by ip-api.com."""

    def __init__(self):
        self.cache: Dict[str, GeoLocation] = {}
        self._provider: str = config.get("geoip", "provider", "ip-api")
        self._rate_limit: int = config.get("geoip", "rate_limit", 45)
        self._req_count: int = 0
        self._window_start: float = time.monotonic()
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock = asyncio.Lock()

    # ── public ────────────────────────────────────────────────────────────────

    async def resolve(self, ip: str) -> GeoLocation:
        """Return GeoLocation for the given IP (cached)."""
        if ip in self.cache:
            return self.cache[ip]

        # Private / loopback → skip network call
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                geo = GeoLocation(ip, "Private", "Local", "Private Network")
                self.cache[ip] = geo
                return geo
        except ValueError:
            pass

        if self._provider == "ip-api" and self._within_rate_limit():
            try:
                geo = await self._lookup_ip_api(ip)
                self.cache[ip] = geo
                return geo
            except Exception:
                pass  # fall through to unknown

        geo = GeoLocation(ip, "Unknown", "Unknown", "Unknown")
        self.cache[ip] = geo
        return geo

    async def close(self):
        """Shutdown aiohttp session."""
        async with self._lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None

    # ── internals ─────────────────────────────────────────────────────────────

    def _within_rate_limit(self) -> bool:
        now = time.monotonic()
        if now - self._window_start >= 60:
            self._req_count = 0
            self._window_start = now
        if self._req_count >= self._rate_limit:
            return False
        self._req_count += 1
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._lock:
            if self._session is None or self._session.closed:
                self._session = aiohttp.ClientSession()
        return self._session

    async def _lookup_ip_api(self, ip: str) -> GeoLocation:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,city,isp,proxy,hosting"
        )
        session = await self._get_session()
        timeout = aiohttp.ClientTimeout(total=4)
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                raise ValueError(f"ip-api HTTP {resp.status}")
            data = await resp.json(content_type=None)
            if data.get("status") != "success":
                raise ValueError("ip-api returned failure")
            return GeoLocation(
                ip=ip,
                country=data.get("country", "Unknown"),
                city=data.get("city", "Unknown"),
                isp=data.get("isp", "Unknown"),
                is_vpn=bool(data.get("proxy", False)),
                is_tor=bool(data.get("hosting", False)),
            )
