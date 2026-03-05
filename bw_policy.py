"""Per-IP bandwidth throttle policy for J.A.R.V.I.S. Proxy.

Matches a client IP against a list of CIDR rules and returns the
bandwidth cap (bytes/sec) for that client.  Rules are checked in
order; the first match wins.  0 means unlimited.

Config section (config.yaml)::

    bandwidth:
      rules:
        - {cidr: "10.0.0.0/8",   bps: 5242880}  # 5 MB/s for internal
        - {cidr: "0.0.0.0/0",    bps: 1048576}  # 1 MB/s for everyone else
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class BWRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    bps: int  # 0 = unlimited


class BWPolicy:
    """Maps client IPs to bandwidth caps via CIDR-ordered rules."""

    def __init__(self, rules: List[Tuple[str, int]] = ()):
        """
        Args:
            rules: list of (cidr_string, bytes_per_second) tuples.
        """
        self._rules: List[BWRule] = []
        for cidr, bps in rules:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._rules.append(BWRule(network=net, bps=bps))
            except ValueError:
                pass

    def get_limit(self, client_ip: str) -> int:
        """Return the bandwidth cap in bytes/sec for client_ip. 0 = unlimited."""
        if not self._rules:
            return 0
        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            return 0
        for rule in self._rules:
            if ip_obj in rule.network:
                return rule.bps
        return 0

    @classmethod
    def from_config(cls, config: dict) -> "BWPolicy":
        """Build from the 'bandwidth' section of config.yaml."""
        bw_cfg = config.get("bandwidth", {})
        raw_rules = bw_cfg.get("rules", [])
        rules = [(r["cidr"], int(r.get("bps", 0))) for r in raw_rules if "cidr" in r]
        return cls(rules=rules)
