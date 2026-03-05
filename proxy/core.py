"""proxy.core — JARVISProxy facade for the enterprise API.

This module exposes the ProxyConfig-aware interface expected by the test suite,
management tooling, and future plugins.

The full async proxy runtime lives in proxy.py at the package root.
"""
from __future__ import annotations

import base64
import ipaddress
from typing import List

from proxy.config import ProxyConfig


class JARVISProxy:
    """Config-aware proxy facade.

    Handles auth checking and exposes the management API.
    The actual async server is in the root-level proxy.py.
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self._auth_user: str | None = config.proxy_auth_user or None
        self._auth_pass: str | None = config.proxy_auth_pass or None
        self._client_allowlist: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._client_denylist:  List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.load_stats()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def load_stats(self) -> None:
        """Load persisted statistics from disk. No-op in test/CLI context."""
        pass

    # ── authentication ────────────────────────────────────────────────────────

    def _check_proxy_auth(self, headers_raw: str) -> bool:
        """Return True if auth is disabled or the supplied credentials are valid.

        Parses ``Proxy-Authorization: Basic <base64>`` from a raw HTTP headers
        string (lines separated by ``\\r\\n``).
        """
        if not self._auth_user:
            return True

        for line in headers_raw.split("\r\n"):
            if line.lower().startswith("proxy-authorization:"):
                _, _, value = line.partition(":")
                value = value.strip()
                if value.lower().startswith("basic "):
                    try:
                        decoded = base64.b64decode(value[6:]).decode("utf-8", errors="replace")
                        user, _, pw = decoded.partition(":")
                        return user == self._auth_user and pw == self._auth_pass
                    except Exception:
                        return False
        return False

    # ── IP access control ─────────────────────────────────────────────────────

    def _check_client_ip(self, client_ip: str) -> bool:
        """Return True if the client IP is permitted to use the proxy.

        If an allowlist is configured only IPs in it are allowed.
        Otherwise the denylist is checked — IPs in it are rejected.
        """
        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            return True  # can't parse, let through

        if self._client_allowlist:
            return any(ip_obj in net for net in self._client_allowlist)
        if self._client_denylist:
            return not any(ip_obj in net for net in self._client_denylist)
        return True

