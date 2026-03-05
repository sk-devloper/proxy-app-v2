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
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except Exception:
            writer.close()
            return

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
