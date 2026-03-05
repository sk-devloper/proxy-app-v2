"""ProxyConfig — typed, validated proxy configuration.

Supports:
  - Dataclass construction with sensible defaults
  - from_file(path)  — load JSON or YAML config file
  - save(path)       — persist as JSON
  - Environment-variable overrides (JARVIS_<FIELD> pattern)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Set


def _default_malicious_domains() -> Set[str]:
    return {"malware.com", "phishing.net", "scam.org"}


def _default_suspicious_tlds() -> Set[str]:
    return {".tk", ".ml", ".ga", ".cf", ".gq"}


@dataclass
class ProxyConfig:
    """All proxy settings in one place with validation."""

    # Core
    host: str = "0.0.0.0"
    port: int = 8888
    ssl_inspection: bool = False
    max_connections: int = 500

    # Auth
    proxy_auth_user: Optional[str] = None
    proxy_auth_pass: Optional[str] = None

    # Timeouts
    connect_timeout: float = 30.0
    read_timeout: float = 10.0
    body_timeout: float = 60.0

    # Health check
    health_check_port: int = 0

    # GeoIP
    geoip_db_path: Optional[str] = None

    # Security
    malicious_domains: Set[str] = field(default_factory=_default_malicious_domains)
    suspicious_tlds: Set[str] = field(default_factory=_default_suspicious_tlds)
    rate_limit_window: int = 60
    rate_limit_max: int = 100

    # Body limits (0 = unlimited)
    max_request_body_size: int = 0
    max_response_body_size: int = 10 * 1024 * 1024

    # Logging
    log_level: str = "INFO"

    # Web UI
    webui_port: int = 8890
    webui_token: str = ""

    # Database
    db_path: str = "logs/jarvis.db"

    def __post_init__(self):
        self._apply_env_overrides()
        self._validate()

    # ── validation ────────────────────────────────────────────────────────────

    def _validate(self):
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port: {self.port}")
        if self.proxy_auth_user and self.proxy_auth_pass is None:
            # Allow user-only config for now — pass can be set later via env
            pass

    # ── env overrides ─────────────────────────────────────────────────────────

    def _apply_env_overrides(self):
        """Override fields with JARVIS_<FIELD_UPPER> environment variables."""
        _int_fields = {"port", "max_connections", "health_check_port", "webui_port",
                       "rate_limit_window", "rate_limit_max",
                       "max_request_body_size", "max_response_body_size"}
        _float_fields = {"connect_timeout", "read_timeout", "body_timeout"}
        _bool_fields = {"ssl_inspection"}

        for fname in _int_fields | _float_fields | _bool_fields | {
            "host", "proxy_auth_user", "proxy_auth_pass",
            "log_level", "webui_token", "db_path", "geoip_db_path",
        }:
            env_key = f"JARVIS_{fname.upper()}"
            env_val = os.environ.get(env_key)
            if env_val is None:
                continue
            if fname in _int_fields:
                setattr(self, fname, int(env_val))
            elif fname in _float_fields:
                setattr(self, fname, float(env_val))
            elif fname in _bool_fields:
                setattr(self, fname, env_val.lower() in ("1", "true", "yes"))
            else:
                setattr(self, fname, env_val)

    # ── serialization ─────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "ProxyConfig":
        """Load config from a JSON or YAML file. Returns defaults on any error."""
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            text = p.read_text()
            if p.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    data = yaml.safe_load(text) or {}
                except ImportError:
                    return cls()
            else:
                data = json.loads(text)
            return cls._from_dict(data)
        except Exception:
            return cls()

    @classmethod
    def _from_dict(cls, data: dict) -> "ProxyConfig":
        """Build a ProxyConfig from a plain dict, ignoring unknown keys."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        # Convert list → set for set-typed fields
        for key in ("malicious_domains", "suspicious_tlds"):
            if key in data and isinstance(data[key], (list, tuple)):
                data[key] = set(data[key])
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def save(self, path: str) -> None:
        """Persist config as JSON (sets converted to sorted lists)."""
        d = asdict(self)
        for key in ("malicious_domains", "suspicious_tlds"):
            if isinstance(d.get(key), (set, frozenset)):
                d[key] = sorted(d[key])
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(d, indent=2))
