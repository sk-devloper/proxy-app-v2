"""Configuration loader for J.A.R.V.I.S. — reads config.yaml, falls back to defaults."""
from pathlib import Path

import yaml

_PATH = Path(__file__).parent / "config.yaml"
_cfg: dict = {}

_DEFAULTS: dict = {
    "proxy":    {"host": "0.0.0.0", "port": 8888, "ssl_inspection": False,
                 "max_connections": 500, "connect_timeout": 30.0, "read_timeout": 10.0},
    "cache":    {"max_size": 10000, "ttl": 36000},
    "geoip":    {"provider": "ip-api", "rate_limit": 45},
    "security": {"rate_limit_window": 6000, "rate_limit_max": 100000},
    "database": {"path": "logs/jarvis.db"},
    "logging":  {
        "level": "DEBUG",
        "max_bytes": 10485760,
        "backup_count": 5,
        "files": {
            "main":        "logs/jarvis.log",
            "access":      "logs/access.log",
            "error":       "logs/error.log",
            "security":    "logs/security.log",
            "performance": "logs/performance.log",
        },
    },
}


def load() -> dict:
    global _cfg
    if _cfg:
        return _cfg
    if _PATH.exists():
        with open(_PATH) as f:
            loaded = yaml.safe_load(f) or {}
        # merge with defaults so missing keys always have a value
        _cfg = {}
        for section, defaults in _DEFAULTS.items():
            _cfg[section] = {**defaults, **loaded.get(section, {})}
    else:
        _cfg = {s: dict(v) for s, v in _DEFAULTS.items()}
    return _cfg


def get(section: str, key: str, default=None):
    return load().get(section, {}).get(key, default)


def reload():
    """Force re-read of config.yaml (call after editing the file)."""
    global _cfg
    _cfg = {}
    return load()
