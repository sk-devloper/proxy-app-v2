"""proxy.security — SecurityAnalyzer with a configurable constructor for enterprise use."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from models import SecurityLevel, ContentType


class SecurityAnalyzer:
    """URL, header, and rate-limit based threat analyser.

    Unlike the flat-module version this accepts explicit constructor params so
    it can be instantiated with custom threat lists and rate-limit settings —
    essential for unit testing and multi-tenant deployments.
    """

    _DEFAULT_MALICIOUS = frozenset({"malware.com", "phishing.net", "scam.org"})
    _DEFAULT_TLDS = frozenset({".tk", ".ml", ".ga", ".cf", ".gq"})

    _ATTACK_TOOLS = frozenset({
        "sqlmap", "nmap", "nikto", "nessus", "masscan",
        "dirbuster", "gobuster", "hydra", "metasploit",
    })

    _URL_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onclick\s*=",
        r"\.\./\.\.",
        r"union\s+select",
        r"drop\s+table",
        r"exec\s*\(",
        r"eval\s*\(",
    ]

    def __init__(
        self,
        rate_limit_window: int = 60,
        rate_limit_max: int = 100,
        malicious_domains: Optional[Set[str]] = None,
        suspicious_tlds: Optional[Set[str]] = None,
    ):
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max = rate_limit_max
        self.malicious_domains: Set[str] = set(
            malicious_domains if malicious_domains is not None else self._DEFAULT_MALICIOUS
        )
        self.suspicious_tlds: Set[str] = set(
            suspicious_tlds if suspicious_tlds is not None else self._DEFAULT_TLDS
        )
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self._URL_PATTERNS]
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)

    # ── public API ────────────────────────────────────────────────────────────

    def analyze_url(self, url: str, host: str) -> Tuple[SecurityLevel, str]:
        """Return (SecurityLevel, reason) for the given URL and hostname."""
        h = host.lower()

        if any(bad in h for bad in self.malicious_domains):
            return SecurityLevel.MALICIOUS, f"Known malicious domain: {host}"

        if any(h.endswith(tld) for tld in self.suspicious_tlds):
            return SecurityLevel.SUSPICIOUS, f"Suspicious TLD: {host}"

        for pattern in self._compiled:
            if pattern.search(url):
                return SecurityLevel.SUSPICIOUS, f"Suspicious pattern in URL"

        if len(url) > 2000:
            return SecurityLevel.SUSPICIOUS, "Unusually long URL"

        return SecurityLevel.SAFE, "OK"

    def analyze_headers(self, headers: Dict[str, str]) -> Tuple[SecurityLevel, str]:
        """Return (SecurityLevel, reason) based on request headers."""
        ua = headers.get("user-agent", "").lower()

        if not ua:
            return SecurityLevel.SUSPICIOUS, "Missing User-Agent"

        if any(tool in ua for tool in self._ATTACK_TOOLS):
            return SecurityLevel.MALICIOUS, f"Attack tool detected in User-Agent"

        return SecurityLevel.SAFE, "OK"

    def check_rate_limit(self, client_ip: str) -> bool:
        """Return False if the client has exceeded the rate limit, True otherwise."""
        now = time.time()
        window = self.rate_limits[client_ip]
        # Purge old entries
        self.rate_limits[client_ip] = [t for t in window if now - t < self.rate_limit_window]
        if len(self.rate_limits[client_ip]) >= self.rate_limit_max:
            return False
        self.rate_limits[client_ip].append(now)
        return True
