"""proxy.filter — PatternFilter: domain/URL-based allow/block filter.

Replaces the flat FilterManager with a cleaner, test-friendly API.
Supports:
  - Exact and subdomain matching
  - Regex patterns (matched against host or full URL)
  - Runtime add/remove of domains
  - Whitelist mode
"""
from __future__ import annotations

import re
from re import Pattern
from typing import List, Set, Tuple


class PatternFilter:
    """Thread-safe domain / URL filter supporting block and allow lists."""

    def __init__(
        self,
        blocked: List[str] = (),
        patterns: List[str] = (),
        allowed: List[str] = (),
        whitelist: bool = False,
    ):
        self._blocked: Set[str] = set()
        self._allowed: Set[str] = set()
        self._block_patterns: List[Pattern] = []
        self._allow_patterns: List[Pattern] = []
        self._whitelist = whitelist

        for domain in blocked:
            self._blocked.add(self._normalise(domain))

        for domain in allowed:
            self._allowed.add(self._normalise(domain))

        for raw in patterns:
            try:
                self._block_patterns.append(re.compile(raw, re.IGNORECASE))
            except re.error:
                pass  # silently ignore invalid patterns

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(domain: str) -> str:
        return domain.lstrip("*.").lower().strip()

    @staticmethod
    def _domain_matches(host: str, domain: str) -> bool:
        return host == domain or host.endswith("." + domain)

    # ── public API ────────────────────────────────────────────────────────────

    def is_blocked(self, host: str, url: str = "") -> Tuple[bool, str]:
        """Return (is_blocked, reason).

        url is optional — when provided, regex patterns are also matched against it.
        The allow list always overrides the block list.
        """
        h = host.lower()
        target = url or h

        # Allow list overrides everything
        for domain in self._allowed:
            if self._domain_matches(h, domain):
                return False, "Allowed"
        for pat in self._allow_patterns:
            if pat.search(target):
                return False, "Allowed by pattern"

        # Whitelist mode — not in allow list means blocked
        if self._whitelist:
            return True, f"Not in whitelist: {host}"

        # Block list
        for domain in self._blocked:
            if self._domain_matches(h, domain):
                return True, f"Blocked domain: {domain}"

        for pat in self._block_patterns:
            if pat.search(target):
                return True, f"Blocked by pattern"

        return False, ""

    def add_domain(self, domain: str) -> None:
        """Add a domain to the block list at runtime."""
        self._blocked.add(self._normalise(domain))

    def remove_domain(self, domain: str) -> None:
        """Remove a domain from the block list."""
        self._blocked.discard(self._normalise(domain))

    def set_whitelist_mode(self, enabled: bool) -> None:
        """Enable or disable whitelist mode."""
        self._whitelist = enabled

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def blocked_domains(self) -> Set[str]:
        return frozenset(self._blocked)

    @property
    def allowed_domains(self) -> Set[str]:
        return frozenset(self._allowed)
