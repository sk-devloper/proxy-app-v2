"""Tests for proxy authentication helper."""

import asyncio
import base64

import pytest

from proxy.config import ProxyConfig
from proxy.core import JARVISProxy


def _proxy(user=None, pw=None):
    cfg = ProxyConfig(proxy_auth_user=user, proxy_auth_pass=pw)
    # Avoid starting server or loading stats; patch away side effects
    import unittest.mock as mock
    with mock.patch.object(JARVISProxy, "load_stats"):
        p = JARVISProxy(cfg)
    return p


def _auth_header(user, pw):
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}"


class TestCheckProxyAuth:
    def test_auth_disabled_always_passes(self):
        p = _proxy()
        assert p._check_proxy_auth("") is True
        assert p._check_proxy_auth("Proxy-Authorization: Basic abc") is True

    def test_correct_credentials(self):
        p = _proxy("alice", "s3cret")
        headers = _auth_header("alice", "s3cret")
        assert p._check_proxy_auth(headers) is True

    def test_wrong_password(self):
        p = _proxy("alice", "s3cret")
        headers = _auth_header("alice", "wrong")
        assert p._check_proxy_auth(headers) is False

    def test_wrong_username(self):
        p = _proxy("alice", "s3cret")
        headers = _auth_header("bob", "s3cret")
        assert p._check_proxy_auth(headers) is False

    def test_missing_header(self):
        p = _proxy("alice", "s3cret")
        assert p._check_proxy_auth("Host: example.com") is False

    def test_malformed_base64(self):
        p = _proxy("alice", "s3cret")
        assert p._check_proxy_auth("Proxy-Authorization: Basic !!!notbase64!!!") is False

    def test_password_with_colon(self):
        # Password containing colon — only the first colon is the separator
        p = _proxy("alice", "pass:word")
        headers = _auth_header("alice", "pass:word")
        assert p._check_proxy_auth(headers) is True
