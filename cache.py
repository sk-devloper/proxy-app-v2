import asyncio
import hashlib
import time
from email.utils import parsedate_to_datetime
from typing import Dict, Optional

from models import CacheEntry, CACHE_MAX_SIZE, CACHE_TTL

# Hop-by-hop headers must never be stored or re-sent from cache
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailers", "transfer-encoding", "upgrade",
})


class AdvancedCache:
    """LRU+TTL HTTP cache with RFC-7234-aware cacheability checks."""

    def __init__(self, max_size: int = CACHE_MAX_SIZE, ttl: int = CACHE_TTL):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = asyncio.Lock()

    # ── key ───────────────────────────────────────────────────────────────────

    def _make_key(self, method: str, url: str, headers: Dict[str, str]) -> str:
        """Cache key: method + URL + Accept-Encoding variant only.

        Accept-Language is intentionally excluded — the same resource is
        almost always served in the same language regardless of the header,
        and including it fragments the cache severely.
        """
        enc = headers.get("accept-encoding", "")
        raw = f"{method}|{url}|{enc}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ── TTL ───────────────────────────────────────────────────────────────────

    def _effective_ttl(self, response_headers: Dict[str, str]) -> float:
        """Return the TTL to use, respecting the server's Cache-Control max-age
        and Expires headers, capped at our configured maximum."""
        cc = response_headers.get("cache-control", "").lower()
        for directive in cc.split(","):
            directive = directive.strip()
            if directive.startswith("max-age="):
                try:
                    server_ttl = float(directive[8:])
                    return min(server_ttl, self.ttl)
                except ValueError:
                    pass
            if directive.startswith("s-maxage="):
                try:
                    server_ttl = float(directive[9:])
                    return min(server_ttl, self.ttl)
                except ValueError:
                    pass

        expires_str = response_headers.get("expires", "")
        if expires_str:
            try:
                exp_ts = parsedate_to_datetime(expires_str).timestamp()
                remaining = exp_ts - time.time()
                if remaining > 0:
                    return min(remaining, self.ttl)
            except Exception:
                pass

        return float(self.ttl)

    # ── cacheability ──────────────────────────────────────────────────────────

    def _is_cacheable(
        self,
        method: str,
        status_code: int,
        response_headers: Dict[str, str],
        request_headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Return True only if this response may be stored.

        Rules (simplified RFC-7234):
        - Only GET and HEAD are cacheable
        - Only a whitelist of status codes
        - no-store or private in Cache-Control → not cacheable
        - Vary: * → not cacheable (can't reproduce the original request)
        - Authorization in request → not cacheable (private per-user data)
        """
        if method not in ("GET", "HEAD"):
            return False

        # Cacheable status codes (RFC-7231 §6.1)
        if status_code not in {200, 203, 204, 300, 301, 404, 405, 410, 414, 501}:
            return False

        cc = response_headers.get("cache-control", "").lower()
        if "no-store" in cc or "private" in cc:
            return False

        if response_headers.get("vary", "").strip() == "*":
            return False

        if request_headers and "authorization" in request_headers:
            return False

        return True

    # ── public API ────────────────────────────────────────────────────────────

    async def get(
        self, method: str, url: str, headers: Dict[str, str]
    ) -> Optional[CacheEntry]:
        """Return a fresh cache entry or None."""
        async with self.lock:
            key = self._make_key(method, url, headers)
            entry = self.cache.get(key)
            if entry is None:
                return None
            if time.time() - entry.timestamp >= entry.ttl:
                del self.cache[key]
                return None
            entry.hit_count += 1
            entry.last_access = time.time()
            return entry

    async def set(
        self,
        method: str,
        url: str,
        request_headers: Dict[str, str],
        status_code: int,
        response_headers: Dict[str, str],
        body: bytes,
    ) -> None:
        """Store a response if it passes cacheability checks."""
        if not self._is_cacheable(method, status_code, response_headers, request_headers):
            return

        # Strip hop-by-hop headers before storing — they must not be re-sent
        storable_headers = {
            k: v for k, v in response_headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

        ttl = self._effective_ttl(response_headers)
        key = self._make_key(method, url, request_headers)

        async with self.lock:
            if len(self.cache) >= self.max_size:
                # Evict least-recently-used entry
                lru_key = min(self.cache, key=lambda k: self.cache[k].last_access)
                del self.cache[lru_key]

            self.cache[key] = CacheEntry(
                url=url,
                status_code=status_code,
                headers=storable_headers,
                body=body,
                timestamp=time.time(),
                size=len(body),
                ttl=ttl,
            )

    def get_stats(self) -> dict:
        total_size = sum(e.size for e in self.cache.values())
        total_hits = sum(e.hit_count for e in self.cache.values())
        return {
            "entries": len(self.cache),
            "size_bytes": total_size,
            "total_hits": total_hits,
        }
