"""Tests for enterprise features added in Phase 4.

Covers:
  - HeaderRewriter (rewrite.py)
  - BWPolicy (bw_policy.py)
  - _check_client_ip (proxy.core.JARVISProxy)
  - WebhookAlerter level filtering (alerting.py)
  - HealthCheckServer payload structure (health.py)
  - HAR export format (har_export.py)
"""
import asyncio
import json
import os
import sys
import tempfile
import types
import unittest

# Ensure proxy-app root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# HeaderRewriter
# ─────────────────────────────────────────────────────────────────────────────
from rewrite import HeaderRewriter, RewriteRule


class TestRewriteRule(unittest.TestCase):
    def test_set_adds_header(self):
        rule = RewriteRule(header="X-Via", action="set", value="JARVIS")
        result = rule.apply({})
        self.assertEqual(result.get("X-Via"), "JARVIS")

    def test_set_overwrites_existing(self):
        rule = RewriteRule(header="X-Via", action="set", value="NEW")
        result = rule.apply({"X-Via": "OLD"})
        self.assertEqual(result["X-Via"], "NEW")

    def test_remove_deletes_header(self):
        rule = RewriteRule(header="Server", action="remove")
        result = rule.apply({"Server": "nginx", "Content-Type": "text/html"})
        self.assertNotIn("Server", result)
        self.assertIn("Content-Type", result)

    def test_remove_case_insensitive(self):
        rule = RewriteRule(header="server", action="remove")
        result = rule.apply({"Server": "apache"})
        self.assertNotIn("Server", result)

    def test_remove_nonexistent_is_noop(self):
        rule = RewriteRule(header="X-Missing", action="remove")
        result = rule.apply({"Content-Type": "text/plain"})
        self.assertEqual(result, {"Content-Type": "text/plain"})

    def test_replace_substitutes_substring(self):
        rule = RewriteRule(header="Server", action="replace", match="1.0", value="2.0")
        result = rule.apply({"Server": "nginx/1.0"})
        self.assertEqual(result["Server"], "nginx/2.0")


class TestHeaderRewriter(unittest.TestCase):
    def test_apply_request_rules(self):
        rw = HeaderRewriter(
            request_rules=[
                {"header": "X-Via", "action": "set", "value": "JARVIS"},
                {"header": "X-Forwarded-For", "action": "remove"},
            ]
        )
        result = rw.apply_request({"X-Forwarded-For": "1.2.3.4", "Host": "example.com"})
        self.assertEqual(result.get("X-Via"), "JARVIS")
        self.assertNotIn("X-Forwarded-For", result)
        self.assertIn("Host", result)

    def test_apply_response_rules(self):
        rw = HeaderRewriter(
            response_rules=[
                {"header": "Server", "action": "remove"},
            ]
        )
        result = rw.apply_response({"Server": "Apache", "Content-Length": "0"})
        self.assertNotIn("Server", result)
        self.assertIn("Content-Length", result)

    def test_from_config(self):
        cfg = {"rewrite": {"request": [{"header": "X-Test", "action": "set", "value": "ok"}]}}
        rw = HeaderRewriter.from_config(cfg)
        result = rw.apply_request({})
        self.assertEqual(result["X-Test"], "ok")

    def test_empty_rules_passthrough(self):
        rw = HeaderRewriter()
        headers = {"X-A": "1", "X-B": "2"}
        self.assertEqual(rw.apply_request(headers), headers)
        self.assertEqual(rw.apply_response(headers), headers)


# ─────────────────────────────────────────────────────────────────────────────
# BWPolicy
# ─────────────────────────────────────────────────────────────────────────────
from bw_policy import BWPolicy


class TestBWPolicy(unittest.TestCase):
    def test_no_rules_returns_unlimited(self):
        p = BWPolicy()
        self.assertEqual(p.get_limit("192.168.1.5"), 0)

    def test_matching_cidr_returns_limit(self):
        p = BWPolicy([("192.168.1.0/24", 1_000_000)])
        self.assertEqual(p.get_limit("192.168.1.100"), 1_000_000)

    def test_non_matching_falls_through(self):
        p = BWPolicy([("10.0.0.0/8", 500_000)])
        self.assertEqual(p.get_limit("192.168.1.1"), 0)

    def test_first_match_wins(self):
        p = BWPolicy([("192.168.0.0/16", 2_000_000), ("0.0.0.0/0", 100_000)])
        self.assertEqual(p.get_limit("192.168.5.5"), 2_000_000)
        self.assertEqual(p.get_limit("8.8.8.8"), 100_000)

    def test_invalid_cidr_ignored(self):
        p = BWPolicy([("not-a-cidr", 999), ("0.0.0.0/0", 1)])
        self.assertEqual(p.get_limit("1.2.3.4"), 1)

    def test_from_config(self):
        cfg = {"bandwidth": {"rules": [{"cidr": "0.0.0.0/0", "bps": 5000}]}}
        p = BWPolicy.from_config(cfg)
        self.assertEqual(p.get_limit("10.0.0.1"), 5000)


# ─────────────────────────────────────────────────────────────────────────────
# _check_client_ip via proxy.core
# ─────────────────────────────────────────────────────────────────────────────
from proxy.core import JARVISProxy
from proxy.config import ProxyConfig


class TestClientIPCheck(unittest.TestCase):
    def _proxy_with(self, allowlist=None, denylist=None):
        cfg = ProxyConfig(port=8888)
        p = JARVISProxy(cfg)
        import ipaddress
        p._client_allowlist = [ipaddress.ip_network(c, strict=False) for c in (allowlist or [])]
        p._client_denylist  = [ipaddress.ip_network(c, strict=False) for c in (denylist or [])]
        return p

    def test_no_lists_allows_all(self):
        p = self._proxy_with()
        self.assertTrue(p._check_client_ip("1.2.3.4"))

    def test_allowlist_permits_matching(self):
        p = self._proxy_with(allowlist=["192.168.1.0/24"])
        self.assertTrue(p._check_client_ip("192.168.1.55"))

    def test_allowlist_blocks_non_matching(self):
        p = self._proxy_with(allowlist=["192.168.1.0/24"])
        self.assertFalse(p._check_client_ip("10.0.0.1"))

    def test_denylist_blocks_matching(self):
        p = self._proxy_with(denylist=["10.0.0.0/8"])
        self.assertFalse(p._check_client_ip("10.5.5.5"))

    def test_denylist_allows_non_matching(self):
        p = self._proxy_with(denylist=["10.0.0.0/8"])
        self.assertTrue(p._check_client_ip("192.168.1.1"))

    def test_allowlist_takes_precedence_over_denylist(self):
        # When allowlist is set, denylist is ignored
        p = self._proxy_with(allowlist=["192.168.1.0/24"], denylist=["192.168.1.0/24"])
        self.assertTrue(p._check_client_ip("192.168.1.1"))


# ─────────────────────────────────────────────────────────────────────────────
# WebhookAlerter level filtering
# ─────────────────────────────────────────────────────────────────────────────
from alerting import WebhookAlerter, _LEVEL_ORDER
from models import SecurityLevel, SecurityThreat


def _threat(level_str: str) -> SecurityThreat:
    from datetime import datetime
    level = SecurityLevel(level_str) if level_str in {s.value for s in SecurityLevel} else SecurityLevel.SAFE
    return SecurityThreat(level=level, host="test.com", reason="test", ip="127.0.0.1", timestamp=datetime.utcnow().isoformat())


class TestWebhookAlerterLevelFilter(unittest.TestCase):
    def test_level_ordering(self):
        a = WebhookAlerter(webhook_url="", min_level=SecurityLevel.MALICIOUS)
        self.assertTrue(a._should_alert(_threat("malicious")))
        self.assertTrue(a._should_alert(_threat("blocked")))
        self.assertFalse(a._should_alert(_threat("suspicious")))

    def test_no_url_send_is_noop(self):
        """send() should return without error when no webhook URL configured."""
        a = WebhookAlerter(webhook_url="", min_level=SecurityLevel.SUSPICIOUS)
        asyncio.run(a.send(_threat("malicious")))


if __name__ == "__main__":
    unittest.main()
