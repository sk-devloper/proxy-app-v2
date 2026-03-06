"""Health check HTTP server for J.A.R.V.I.S. Proxy.

Starts a lightweight asyncio HTTP server on a configurable port.
Returns JSON on GET /health.  Zero external dependencies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proxy import JARVISProxy

log = logging.getLogger("JARVIS.health")

_VERSION = "5.0.0"


class HealthCheckServer:
    """Serves GET /health → JSON status document."""

    def __init__(self, proxy: "JARVISProxy", port: int):
        self.proxy = proxy
        self.port = port
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        if not self.port:
            return
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", self.port
        )
        log.info(f"Health check server listening on port {self.port}")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except Exception:
            writer.close()
            return

        # Determine request path
        path = "/"
        try:
            first_line = raw.split(b"\r\n")[0].decode(errors="ignore")
            path = first_line.split()[1]
        except Exception:
            pass

        if path == "/metrics":
            body = self._build_prometheus_metrics().encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
        else:
            payload = self._build_payload()
            body = json.dumps(payload, indent=2).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
        try:
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    def _build_prometheus_metrics(self) -> str:
        """Render Prometheus text exposition format (no external deps)."""
        s = self.proxy.stats
        uptime = time.time() - s.start_time
        cache_total = s.cache_hits + s.cache_misses
        cache_hit_rate = s.cache_hits / cache_total if cache_total else 0.0
        cache_stats = self.proxy.cache.get_stats()

        lines = [
            "# HELP jarvis_uptime_seconds Proxy uptime in seconds",
            "# TYPE jarvis_uptime_seconds gauge",
            f"jarvis_uptime_seconds {uptime:.1f}",
            "",
            "# HELP jarvis_requests_total Total number of proxied requests",
            "# TYPE jarvis_requests_total counter",
            f"jarvis_requests_total {s.total_requests}",
            "",
            "# HELP jarvis_errors_total Total number of proxy errors",
            "# TYPE jarvis_errors_total counter",
            f"jarvis_errors_total {s.total_errors}",
            "",
            "# HELP jarvis_active_connections Current active connections",
            "# TYPE jarvis_active_connections gauge",
            f"jarvis_active_connections {s.active_connections}",
            "",
            "# HELP jarvis_peak_connections Peak simultaneous connections",
            "# TYPE jarvis_peak_connections gauge",
            f"jarvis_peak_connections {s.peak_connections}",
            "",
            "# HELP jarvis_cache_hits_total Cache hit count",
            "# TYPE jarvis_cache_hits_total counter",
            f"jarvis_cache_hits_total {s.cache_hits}",
            "",
            "# HELP jarvis_cache_misses_total Cache miss count",
            "# TYPE jarvis_cache_misses_total counter",
            f"jarvis_cache_misses_total {s.cache_misses}",
            "",
            "# HELP jarvis_cache_hit_ratio Cache hit ratio (0–1)",
            "# TYPE jarvis_cache_hit_ratio gauge",
            f"jarvis_cache_hit_ratio {cache_hit_rate:.4f}",
            "",
            "# HELP jarvis_cache_entries Current number of entries in cache",
            "# TYPE jarvis_cache_entries gauge",
            f"jarvis_cache_entries {cache_stats['entries']}",
            "",
            "# HELP jarvis_bytes_sent_total Total bytes sent to clients",
            "# TYPE jarvis_bytes_sent_total counter",
            f"jarvis_bytes_sent_total {s.total_bytes_sent}",
            "",
            "# HELP jarvis_bytes_received_total Total bytes received from upstream",
            "# TYPE jarvis_bytes_received_total counter",
            f"jarvis_bytes_received_total {s.total_bytes_received}",
            "",
            "# HELP jarvis_threats_blocked_total Total security threats blocked",
            "# TYPE jarvis_threats_blocked_total counter",
            f"jarvis_threats_blocked_total {s.threats_blocked}",
            "",
            "# HELP jarvis_unique_clients_total Distinct client IPs seen",
            "# TYPE jarvis_unique_clients_total gauge",
            f"jarvis_unique_clients_total {len(s.unique_clients)}",
            "",
        ]
        return "\n".join(lines) + "\n"

    def _build_payload(self) -> dict:
        s = self.proxy.stats
        uptime = time.time() - s.start_time
        cache_total = s.cache_hits + s.cache_misses
        cache_stats = self.proxy.cache.get_stats()
        return {
            "status": "ok",
            "version": _VERSION,
            "uptime_seconds": round(uptime, 1),
            "active_connections": s.active_connections,
            "total_requests": s.total_requests,
            "total_errors": s.total_errors,
            "cache_hits": s.cache_hits,
            "cache_misses": s.cache_misses,
            "cache_hit_rate": round(s.cache_hits / cache_total * 100, 1) if cache_total else 0,
            "cache_entries": cache_stats["entries"],
            "cache_size_bytes": cache_stats["size_bytes"],
            "threats_blocked": s.threats_blocked,
            "bytes_sent": s.total_bytes_sent,
            "bytes_received": s.total_bytes_received,
        }
