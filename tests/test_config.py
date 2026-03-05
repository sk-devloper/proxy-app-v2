"""Tests for ProxyConfig loading and defaults."""

import json
import os
import tempfile

import pytest

from proxy.config import ProxyConfig


def test_defaults():
    c = ProxyConfig()
    assert c.host == "0.0.0.0"
    assert c.port == 8888
    assert c.proxy_auth_user is None
    assert c.proxy_auth_pass is None
    assert c.health_check_port == 0
    assert c.geoip_db_path is None
    assert len(c.malicious_domains) > 0
    assert len(c.suspicious_tlds) > 0
    assert c.max_request_body_size == 0
    assert c.max_response_body_size == 10 * 1024 * 1024


def test_from_file_happy_path(tmp_path):
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({
        "port": 9999,
        "proxy_auth_user": "alice",
        "proxy_auth_pass": "secret",
        "health_check_port": 8080,
        "log_level": "DEBUG",
    }))
    c = ProxyConfig.from_file(str(cfg_file))
    assert c.port == 9999
    assert c.proxy_auth_user == "alice"
    assert c.proxy_auth_pass == "secret"
    assert c.health_check_port == 8080
    assert c.log_level == "DEBUG"


def test_from_file_missing_returns_defaults(tmp_path):
    c = ProxyConfig.from_file(str(tmp_path / "nonexistent.json"))
    assert c.port == 8888


def test_from_file_invalid_json_returns_defaults(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    c = ProxyConfig.from_file(str(bad))
    assert c.port == 8888


def test_save_and_reload(tmp_path):
    cfg_file = str(tmp_path / "config.json")
    c = ProxyConfig(port=7777, proxy_auth_user="bob")
    c.save(cfg_file)
    c2 = ProxyConfig.from_file(cfg_file)
    assert c2.port == 7777
    assert c2.proxy_auth_user == "bob"
