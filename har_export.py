"""HAR 1.2 export for J.A.R.V.I.S. Proxy.

Serialises recent ConnectionMetrics to the HTTP Archive (HAR) 1.2 format.
Spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from proxy import JARVISProxy

from models import ConnectionMetrics

log = logging.getLogger("JARVIS.har")

_HAR_VERSION = "5.0.0"
_CREATOR = "J.A.R.V.I.S. Proxy"


def _entry(m: ConnectionMetrics) -> dict:
    """Convert a ConnectionMetrics instance to a HAR entry."""
    timings = {
        "send": 0,
        "wait": round(m.response_time_ms or 0, 3),
        "receive": 0,
        "dns": round(m.dns.dns_time_ms if m.dns else 0, 3),
        "connect": round(m.tcp_connect_ms or 0, 3),
        "ssl": -1,
    }
    total_time = sum(v for v in timings.values() if v >= 0)

    req_headers = [
        {"name": k, "value": v}
        for k, v in (m.request_headers or {}).items()
    ]
    resp_headers = [
        {"name": k, "value": v}
        for k, v in (m.response_headers or {}).items()
    ]

    return {
        "startedDateTime": m.timestamp + "Z" if m.timestamp else "",
        "time": round(total_time, 3),
        "request": {
            "method": m.method or "CONNECT",
            "url": m.url or f"https://{m.host}:{m.port}/",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": req_headers,
            "queryString": [],
            "headersSize": -1,
            "bodySize": -1,
        },
        "response": {
            "status": m.status_code or 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": resp_headers,
            "content": {
                "size": m.body_bytes or 0,
                "mimeType": (
                    m.content_type.value if m.content_type else "application/octet-stream"
                ),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": m.body_bytes or -1,
        },
        "cache": {"beforeRequest": None, "afterRequest": None},
        "timings": timings,
        "_cached": m.cached,
        "_securityLevel": m.security_level.value if m.security_level else "safe",
        "_clientIP": m.client_ip or "",
    }


def export(proxy: "JARVISProxy", path: str = "logs/export.har") -> str:
    """Write HAR file from proxy.stats.recent_requests. Returns the path written."""
    requests: List[ConnectionMetrics] = list(proxy.stats.recent_requests)
    entries = []
    for m in requests:
        try:
            entries.append(_entry(m))
        except Exception as exc:
            log.debug(f"Skipping HAR entry: {exc}")

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": _CREATOR, "version": _HAR_VERSION},
            "browser": {"name": _CREATOR, "version": _HAR_VERSION},
            "pages": [],
            "entries": entries,
        }
    }

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(har, indent=2, default=str))
    log.info(f"HAR export written to {path} ({len(entries)} entries)")
    return str(out)
