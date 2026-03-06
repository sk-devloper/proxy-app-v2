"""Category-based URL filtering for J.A.R.V.I.S. Proxy.

Allows blocking or allowing traffic by content category (e.g. adult, gambling,
malware, social) without requiring an external paid API.

Works on two layers:
  1. Built-in category rules — domain → category mapping in config.yaml
  2. Optional external lookup — calls a free/configurable categorization API
     and caches the result.

Config section (config.yaml)::

    categorizer:
      enabled: false
      block_categories:          # categories to block
        - adult
        - gambling
        - malware
      rules:                     # manual domain → category assignments
        - {domain: "*.example-adult.com",  category: adult}
        - {domain: "casino.com",           category: gambling}
      external:
        enabled: false           # set true to call an external API
        url: ""                  # POST {domain} → {category: "..."}
        timeout: 3.0
        cache_ttl: 3600
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import ssl
import time
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("JARVIS.categorizer")

# Built-in heuristic category detection based on TLD/keyword patterns
_BUILTIN_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bporn\b|\bxxx\b|\badult\b|\bsex\b",         re.I), "adult"),
    (re.compile(r"\bcasino\b|\bbet\b|\bgambling\b|\bpoker\b",   re.I), "gambling"),
    (re.compile(r"\bmalware\b|\bphish\b|\bvirus\b|\btrojan\b",  re.I), "malware"),
    (re.compile(r"\bfacebook\b|\binstagram\b|\btiktok\b|\btwitter\b|\bx\.com", re.I), "social"),
    (re.compile(r"\bads?\b|\btracker\b|\banalytics\b|\btelemetry\b", re.I), "ads"),
    (re.compile(r"\bwarez\b|\bpirat\b|\btorrent\b|\bcrack\b",   re.I), "piracy"),
]


class CategoryFilter:
    """Categorize domains and block/allow by category."""

    def __init__(
        self,
        block_categories: List[str] = (),
        manual_rules: List[dict] = (),
        external_url: str = "",
        external_timeout: float = 3.0,
        external_cache_ttl: int = 3600,
    ):
        self.block_categories: Set[str] = {c.lower() for c in block_categories}
        self._manual: List[Tuple[str, str]] = [
            (r.get("domain", "").lower(), r.get("category", "").lower())
            for r in manual_rules
        ]
        self._ext_url      = external_url
        self._ext_timeout  = external_timeout
        self._ext_cache_ttl = external_cache_ttl
        self._ext_cache: Dict[str, Tuple[str, float]] = {}
        self._ssl_ctx = ssl.create_default_context()

    def categorize(self, domain: str) -> str:
        """Return the best-guess category for *domain*, or 'unknown'."""
        d = domain.lower()

        # 1. Manual rules (supports fnmatch wildcards: *.example.com)
        for pattern, category in self._manual:
            if fnmatch.fnmatch(d, pattern):
                return category

        # 2. Built-in heuristics
        for rx, category in _BUILTIN_RULES:
            if rx.search(d):
                return category

        return "unknown"

    async def categorize_with_external(self, domain: str) -> str:
        """Categorize, optionally calling the external API on cache miss."""
        category = self.categorize(domain)
        if category != "unknown" or not self._ext_url:
            return category

        # Check external cache
        if domain in self._ext_cache:
            cached_cat, expiry = self._ext_cache[domain]
            if time.monotonic() < expiry:
                return cached_cat

        try:
            import asyncio
            loop = asyncio.get_running_loop()
            category = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_external_lookup, domain),
                timeout=self._ext_timeout,
            )
            self._ext_cache[domain] = (category, time.monotonic() + self._ext_cache_ttl)
        except Exception as exc:
            log.debug("External categorizer failed for %s: %s", domain, exc)

        return category

    def _sync_external_lookup(self, domain: str) -> str:
        body = json.dumps({"domain": domain}).encode()
        req = urllib.request.Request(
            self._ext_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._ext_timeout, context=self._ssl_ctx) as resp:
            data = json.loads(resp.read())
        return data.get("category", "unknown").lower()

    def is_blocked(self, category: str) -> bool:
        """Return True if *category* is in the block list."""
        return category.lower() in self.block_categories

    @classmethod
    def from_config(cls, config: dict) -> Optional["CategoryFilter"]:
        """Return a CategoryFilter if enabled in config, else None."""
        cfg = config.get("categorizer", {})
        if not cfg.get("enabled", False):
            return None
        ext = cfg.get("external", {})
        return cls(
            block_categories    = cfg.get("block_categories", []),
            manual_rules        = cfg.get("rules", []),
            external_url        = ext.get("url", "") if ext.get("enabled") else "",
            external_timeout    = float(ext.get("timeout", 3.0)),
            external_cache_ttl  = int(ext.get("cache_ttl", 3600)),
        )
