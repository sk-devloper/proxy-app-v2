"""
FilterManager — file-based domain/URL filtering with subdomain matching and hot-reload.

File format (blocklist.txt / allowlist.txt):
  # Comment lines start with #
  example.com          # blocks example.com and *.example.com
  *.ads.com            # leading *. is stripped — same as ads.com
  regex:.*\\.ad\\..*   # full-URL regex match (prefix with "regex:")
"""
import re
import time
from pathlib import Path
from typing import List, Set
from re import Pattern


class FilterManager:
    """Loads domain/pattern filter lists from files with hot-reload."""

    def __init__(
        self,
        blocklist_file: str = "filters/blocklist.txt",
        allowlist_file: str = "filters/allowlist.txt",
        reload_interval: int = 60,
    ):
        self.blocklist_file = Path(blocklist_file)
        self.allowlist_file = Path(allowlist_file)
        self.reload_interval = reload_interval

        self._blocked_domains: Set[str] = set()
        self._allowed_domains: Set[str] = set()
        self._blocked_patterns: List[Pattern] = []
        self._allowed_patterns: List[Pattern] = []
        self._last_load: float = 0.0

        self.load()

    # ── file parsing ──────────────────────────────────────────────────────────

    def _parse_file(self, path: Path):
        domains: Set[str] = set()
        patterns: List[Pattern] = []
        if not path.exists():
            return domains, patterns
        for raw in path.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip inline comments
            if " #" in line:
                line = line[:line.index(" #")].strip()
            if line.startswith("regex:"):
                try:
                    patterns.append(re.compile(line[6:].strip(), re.IGNORECASE))
                except re.error:
                    pass
            else:
                # Normalise: strip leading wildcard and lowercase
                domains.add(line.lstrip("*.").lower())
        return domains, patterns

    def load(self):
        """(Re)load both filter files from disk."""
        self._blocked_domains, self._blocked_patterns = self._parse_file(self.blocklist_file)
        self._allowed_domains, self._allowed_patterns = self._parse_file(self.allowlist_file)
        self._last_load = time.time()

    def maybe_reload(self):
        """Reload if the reload interval has elapsed — called on every check."""
        if time.time() - self._last_load >= self.reload_interval:
            self.load()

    # ── matching ──────────────────────────────────────────────────────────────

    @staticmethod
    def _domain_matches(host: str, domain: str) -> bool:
        """Return True if host equals domain or is a subdomain of domain."""
        return host == domain or host.endswith("." + domain)

    def is_blocked(self, host: str) -> bool:
        """Return True if host matches any entry in the blocklist."""
        self.maybe_reload()
        h = host.lower()
        for domain in self._blocked_domains:
            if self._domain_matches(h, domain):
                return True
        for pattern in self._blocked_patterns:
            if pattern.search(h):
                return True
        return False

    def is_bypassed(self, host: str) -> bool:
        """Return True if host is explicitly in the allowlist (overrides blocklist)."""
        h = host.lower()
        for domain in self._allowed_domains:
            if self._domain_matches(h, domain):
                return True
        for pattern in self._allowed_patterns:
            if pattern.search(h):
                return True
        return False

    # ── stats helpers ─────────────────────────────────────────────────────────

    @property
    def blocked_domains(self) -> Set[str]:
        return set(self._blocked_domains)

    @property
    def allowed_domains(self) -> Set[str]:
        return set(self._allowed_domains)
