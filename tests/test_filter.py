"""Tests for PatternFilter."""

import pytest

from proxy.filter import PatternFilter


def _f(blocked=(), patterns=(), allowed=(), whitelist=False):
    return PatternFilter(list(blocked), list(patterns), list(allowed), whitelist)


class TestDomainBlocking:
    def test_exact_domain_blocked(self):
        f = _f(blocked=["ads.example.com"])
        blocked, reason = f.is_blocked("ads.example.com")
        assert blocked
        assert "ads.example.com" in reason

    def test_subdomain_of_blocked_domain(self):
        f = _f(blocked=["example.com"])
        blocked, _ = f.is_blocked("sub.example.com")
        assert blocked

    def test_unrelated_domain_not_blocked(self):
        f = _f(blocked=["ads.example.com"])
        blocked, _ = f.is_blocked("safe.example.com")
        assert not blocked

    def test_add_and_remove_domain(self):
        f = _f()
        f.add_domain("bad.com")
        assert f.is_blocked("bad.com")[0]
        f.remove_domain("bad.com")
        assert not f.is_blocked("bad.com")[0]


class TestPatternBlocking:
    def test_regex_pattern_matches_url(self):
        f = _f(patterns=[r".*tracker.*"])
        blocked, reason = f.is_blocked("example.com", "http://example.com/tracker/pixel.gif")
        assert blocked

    def test_regex_pattern_no_match(self):
        f = _f(patterns=[r".*tracker.*"])
        blocked, _ = f.is_blocked("example.com", "http://example.com/page")
        assert not blocked

    def test_invalid_regex_ignored(self):
        # Should not raise; invalid pattern is silently skipped
        f = _f(patterns=["[invalid"])
        blocked, _ = f.is_blocked("example.com")
        assert not blocked


class TestWhitelistMode:
    def test_allowed_domain_passes(self):
        f = _f(allowed=["trusted.com"], whitelist=True)
        blocked, _ = f.is_blocked("trusted.com")
        assert not blocked

    def test_allowed_subdomain_passes(self):
        f = _f(allowed=["trusted.com"], whitelist=True)
        blocked, _ = f.is_blocked("api.trusted.com")
        assert not blocked

    def test_unlisted_domain_blocked_in_whitelist_mode(self):
        f = _f(allowed=["trusted.com"], whitelist=True)
        blocked, reason = f.is_blocked("untrusted.com")
        assert blocked
        assert "whitelist" in reason.lower() or "Not in whitelist" in reason

    def test_whitelist_mode_off_unlisted_passes(self):
        f = _f(allowed=["trusted.com"], whitelist=False)
        blocked, _ = f.is_blocked("untrusted.com")
        assert not blocked

    def test_set_whitelist_mode(self):
        f = _f(allowed=["trusted.com"], whitelist=False)
        assert not f.is_blocked("other.com")[0]
        f.set_whitelist_mode(True)
        assert f.is_blocked("other.com")[0]
