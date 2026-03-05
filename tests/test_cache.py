"""Tests for AdvancedCache."""

import asyncio
import time

import pytest

from proxy.cache import AdvancedCache, _parse_max_age


# ---- _parse_max_age unit tests ----

def test_parse_max_age_max_age():
    assert _parse_max_age("max-age=300", 60) == 300

def test_parse_max_age_s_maxage_preferred():
    assert _parse_max_age("max-age=60, s-maxage=300", 10) == 300

def test_parse_max_age_default_when_missing():
    assert _parse_max_age("no-store", 42) == 42

def test_parse_max_age_zero():
    assert _parse_max_age("max-age=0", 60) == 0

def test_parse_max_age_negative_clamped():
    assert _parse_max_age("max-age=-5", 60) == 0


# ---- AdvancedCache async tests ----

@pytest.fixture
def cache():
    return AdvancedCache(max_size=10, ttl=3600)


def run(coro):
    return asyncio.run(coro)


def test_cache_miss(cache):
    entry = run(cache.get("GET", "http://example.com/", {}))
    assert entry is None


def test_cache_set_and_get(cache):
    run(cache.set("GET", "http://example.com/", {}, 200, {"cache-control": "max-age=3600"}, b"hello"))
    entry = run(cache.get("GET", "http://example.com/", {}))
    assert entry is not None
    assert entry.body == b"hello"
    assert entry.status_code == 200


def test_cache_only_stores_get_head(cache):
    run(cache.set("POST", "http://example.com/", {}, 200, {}, b"data"))
    assert run(cache.get("POST", "http://example.com/", {})) is None


def test_cache_no_store_not_cached(cache):
    run(cache.set("GET", "http://example.com/ns", {}, 200, {"cache-control": "no-store"}, b"data"))
    assert run(cache.get("GET", "http://example.com/ns", {})) is None


def test_cache_private_not_cached(cache):
    run(cache.set("GET", "http://example.com/priv", {}, 200, {"cache-control": "private"}, b"data"))
    assert run(cache.get("GET", "http://example.com/priv", {})) is None


def test_cache_respects_max_age_expiry(cache):
    # Use a very short TTL entry
    c = AdvancedCache(max_size=10, ttl=1)
    run(c.set("GET", "http://x.com/", {}, 200, {"cache-control": "max-age=1"}, b"x"))
    time.sleep(1.1)
    assert run(c.get("GET", "http://x.com/", {})) is None


def test_cache_hit_increments_counter(cache):
    run(cache.set("GET", "http://example.com/cnt", {}, 200, {"cache-control": "max-age=3600"}, b"v"))
    run(cache.get("GET", "http://example.com/cnt", {}))
    run(cache.get("GET", "http://example.com/cnt", {}))
    entry = run(cache.get("GET", "http://example.com/cnt", {}))
    assert entry.hit_count == 3


def test_cache_lru_eviction(cache):
    # Fill beyond max_size=10 with unique URLs; oldest should be evicted
    for i in range(11):
        run(cache.set("GET", f"http://example.com/{i}", {}, 200,
                      {"cache-control": "max-age=3600"}, b"data"))
    stats = cache.get_stats()
    assert stats["entries"] <= 10


def test_cache_stats(cache):
    run(cache.set("GET", "http://example.com/s", {}, 200, {"cache-control": "max-age=3600"}, b"abc"))
    stats = cache.get_stats()
    assert stats["entries"] == 1
    assert stats["size_bytes"] == 3
