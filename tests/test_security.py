"""Tests for SecurityAnalyzer."""

import time

import pytest

from proxy.security import SecurityAnalyzer
from proxy.models import SecurityLevel


def _sa(**kwargs):
    return SecurityAnalyzer(rate_limit_window=60, rate_limit_max=5, **kwargs)


class TestURLAnalysis:
    def test_safe_url(self):
        sa = _sa()
        level, _ = sa.analyze_url("http://example.com/page", "example.com")
        assert level == SecurityLevel.SAFE

    def test_known_malicious_domain(self):
        sa = _sa()
        level, reason = sa.analyze_url("http://malware.com/", "malware.com")
        assert level == SecurityLevel.MALICIOUS

    def test_custom_malicious_domain(self):
        sa = _sa(malicious_domains=["evil.com"])
        level, _ = sa.analyze_url("http://evil.com/", "evil.com")
        assert level == SecurityLevel.MALICIOUS

    def test_suspicious_tld(self):
        sa = _sa()
        level, _ = sa.analyze_url("http://example.tk/", "example.tk")
        assert level == SecurityLevel.SUSPICIOUS

    def test_custom_suspicious_tld(self):
        sa = _sa(suspicious_tlds=[".bad"])
        level, _ = sa.analyze_url("http://example.bad/", "example.bad")
        assert level == SecurityLevel.SUSPICIOUS

    def test_xss_in_url(self):
        sa = _sa()
        level, _ = sa.analyze_url("http://example.com/?q=<script>alert(1)</script>", "example.com")
        assert level == SecurityLevel.SUSPICIOUS

    def test_sql_injection_in_url(self):
        sa = _sa()
        level, _ = sa.analyze_url("http://example.com/?id=1 union select 1,2,3", "example.com")
        assert level == SecurityLevel.SUSPICIOUS

    def test_long_url_suspicious(self):
        sa = _sa()
        long_url = "http://example.com/" + "a" * 2001
        level, _ = sa.analyze_url(long_url, "example.com")
        assert level == SecurityLevel.SUSPICIOUS


class TestHeaderAnalysis:
    def test_safe_headers(self):
        sa = _sa()
        level, _ = sa.analyze_headers({"user-agent": "Mozilla/5.0"})
        assert level == SecurityLevel.SAFE

    def test_missing_user_agent(self):
        sa = _sa()
        level, _ = sa.analyze_headers({})
        assert level == SecurityLevel.SUSPICIOUS

    def test_attack_tool_user_agent(self):
        sa = _sa()
        level, _ = sa.analyze_headers({"user-agent": "sqlmap/1.0"})
        assert level == SecurityLevel.MALICIOUS


class TestRateLimit:
    def test_allows_up_to_limit(self):
        sa = _sa()
        for _ in range(5):
            assert sa.check_rate_limit("1.2.3.4")

    def test_blocks_over_limit(self):
        sa = _sa()
        for _ in range(5):
            sa.check_rate_limit("1.2.3.4")
        assert not sa.check_rate_limit("1.2.3.4")

    def test_different_ips_independent(self):
        sa = _sa()
        for _ in range(5):
            sa.check_rate_limit("1.1.1.1")
        # Different IP should still be allowed
        assert sa.check_rate_limit("2.2.2.2")
