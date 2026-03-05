import asyncio
import gzip
import json
import logging
import os
import pickle
import re
import socket
import ssl
import base64
import sys
import time
from collections import deque
from dataclasses import asdict
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qs

from rich.console import Console

import config as cfg
from models import (
    ConnectionMetrics, ContentType, DNSInfo, GeoLocation, ProxyStats,
    SecurityLevel, SecurityThreat, SSLInfo,
    BUFFER_SIZE, DEFAULT_TIMEOUT, MAX_HEADER_SIZE, STATS_UPDATE_INTERVAL,
)
from ssl_manager import SSLCertificateManager
from cache import AdvancedCache
from security import SecurityAnalyzer, TrafficInspector
from geoip import GeoIPResolver
from database import DatabaseLogger
from filter_manager import FilterManager

class JARVISProxy:
    """Iron Man's J.A.R.V.I.S. - Just A Rather Very Intelligent System Proxy"""

    def __init__(self, host: str = "0.0.0.0", port: int = 8888, enable_ssl_inspection: bool = False):
        self.host = host
        self.port = port
        self.stats = ProxyStats()
        self.console = Console()
        self.running = False
        self.server = None
        self.tui_task = None
        self.enable_ssl_inspection = enable_ssl_inspection

        # SSL Certificate Manager
        if enable_ssl_inspection:
            self.ssl_manager = SSLCertificateManager()
        else:
            self.ssl_manager = None

        # Advanced components
        self.cache = AdvancedCache()
        self.security = SecurityAnalyzer()
        self.inspector = TrafficInspector()
        self.geoip = GeoIPResolver()
        self.db = DatabaseLogger()

        # Filter manager (file-based blocklist / allowlist with hot-reload)
        _filter_cfg = cfg.load().get("filter", {})
        self.filter_mgr = FilterManager(
            blocklist_file=_filter_cfg.get("blocklist_file", "filters/blocklist.txt"),
            allowlist_file=_filter_cfg.get("allowlist_file", "filters/allowlist.txt"),
            reload_interval=int(_filter_cfg.get("reload_interval", 60)),
        )
        # Sync extra bypass domains from config into filter_mgr's allowed set
        for _d in _filter_cfg.get("bypass_domains", []):
            self.filter_mgr._allowed_domains.add(_d.lower().lstrip("*."))

        # DNS cache
        self.dns_cache: Dict[str, Tuple[DNSInfo, float]] = {}
        self.dns_cache_ttl = 300

        # Bandwidth throttling
        self.bandwidth_limit = 0

        # Per-IP bandwidth policy (replaces single global limit)
        from bw_policy import BWPolicy
        self.bw_policy = BWPolicy.from_config(cfg.load())

        # Header rewrite rules
        from rewrite import HeaderRewriter
        self.header_rewriter = HeaderRewriter.from_config(cfg.load())

        # Client IP allowlist / denylist (CIDR lists)
        import ipaddress as _ipaddress
        _sec_cfg = cfg.load().get("security", {})
        self._client_allowlist = [
            _ipaddress.ip_network(c, strict=False)
            for c in _sec_cfg.get("client_allowlist", [])
        ]
        self._client_denylist = [
            _ipaddress.ip_network(c, strict=False)
            for c in _sec_cfg.get("client_denylist", [])
        ]

        # Proxy authentication (empty string = disabled)
        self._auth_user: str | None = cfg.get("proxy", "auth_user", None) or None
        self._auth_pass: str | None = cfg.get("proxy", "auth_pass", None) or None

        # Upstream proxy chaining  (e.g. corporate proxy)
        _upstream = cfg.get("proxy", "upstream_proxy", "") or ""
        if _upstream and ":" in _upstream:
            _up_host, _, _up_port = _upstream.rpartition(":")
            self._upstream_host: str | None = _up_host
            self._upstream_port: int = int(_up_port)
        else:
            self._upstream_host = None
            self._upstream_port = 0

        # Connection semaphore — prevents runaway concurrency
        _max_conn = cfg.get("proxy", "max_connections", 500)
        self._conn_sem = asyncio.Semaphore(_max_conn)

        # Timeouts from config
        self._connect_timeout = cfg.get("proxy", "connect_timeout", 30.0)
        self._read_timeout    = cfg.get("proxy", "read_timeout", 10.0)
        self._body_timeout    = cfg.get("proxy", "body_timeout",  60.0)

        # ── Logging setup ─────────────────────────────────────────────────────
        Path("logs").mkdir(exist_ok=True)

        _log_cfg     = cfg.load().get("logging", {})
        _log_files   = _log_cfg.get("files", {})
        _max_bytes   = _log_cfg.get("max_bytes",    10 * 1024 * 1024)
        _backups     = _log_cfg.get("backup_count", 5)
        _level_str   = _log_cfg.get("level", "DEBUG")
        _level       = getattr(logging, _level_str.upper(), logging.DEBUG)
        _use_json    = _log_cfg.get("format", "text") == "json"

        if _use_json:
            import json as _json
            import time as _time_mod

            class _JsonFormatter(logging.Formatter):
                def format(self, record):
                    log_obj = {
                        "ts": _time_mod.strftime("%Y-%m-%dT%H:%M:%S", _time_mod.gmtime(record.created)),
                        "level": record.levelname,
                        "logger": record.name,
                        "msg": record.getMessage(),
                    }
                    if record.exc_info:
                        log_obj["exc"] = self.formatException(record.exc_info)
                    return _json.dumps(log_obj)

            _fmt_detail = _JsonFormatter()
            _fmt_plain  = _JsonFormatter()
        else:
            _fmt_detail  = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
            _fmt_plain   = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")

        def _make_handler(path: str, level=logging.DEBUG, fmt=_fmt_detail):
            from logging.handlers import RotatingFileHandler
            h = RotatingFileHandler(path, maxBytes=_max_bytes, backupCount=_backups)
            h.setLevel(level)
            h.setFormatter(fmt)
            return h

        # Root JARVIS logger — everything
        self.logger = logging.getLogger("JARVIS")
        self.logger.setLevel(_level)
        if not self.logger.handlers:
            self.logger.addHandler(_make_handler(
                _log_files.get("main", "logs/jarvis.log"), _level))

        # Access log — one structured line per request (INFO+)
        self.access_log = logging.getLogger("JARVIS.access")
        self.access_log.setLevel(logging.INFO)
        self.access_log.propagate = False
        if not self.access_log.handlers:
            self.access_log.addHandler(_make_handler(
                _log_files.get("access", "logs/access.log"),
                logging.INFO, _fmt_plain))

        # Error log — WARNING+ only
        self.error_log = logging.getLogger("JARVIS.error")
        self.error_log.setLevel(logging.WARNING)
        self.error_log.propagate = False
        if not self.error_log.handlers:
            self.error_log.addHandler(_make_handler(
                _log_files.get("error", "logs/error.log"),
                logging.WARNING, _fmt_detail))

        # Security log — all security events
        self.sec_log = logging.getLogger("JARVIS.security")
        self.sec_log.setLevel(logging.DEBUG)
        self.sec_log.propagate = False
        if not self.sec_log.handlers:
            self.sec_log.addHandler(_make_handler(
                _log_files.get("security", "logs/security.log"),
                logging.DEBUG, _fmt_plain))

        # Performance log — periodic snapshots
        self.perf_log = logging.getLogger("JARVIS.performance")
        self.perf_log.setLevel(logging.INFO)
        self.perf_log.propagate = False
        if not self.perf_log.handlers:
            self.perf_log.addHandler(_make_handler(
                _log_files.get("performance", "logs/performance.log"),
                logging.INFO, _fmt_plain))

        self.logger.info("J.A.R.V.I.S. logging initialised — "
                         f"level={_level_str} max_conn={_max_conn}")

        # Alert system
        self.alerts: deque = deque(maxlen=100)

        # Webhook alerter (disabled if no URL configured)
        _alert_cfg = cfg.load().get("alerting", {})
        _webhook_url = _alert_cfg.get("webhook_url", "") or ""
        _min_level_str = _alert_cfg.get("min_level", "malicious").lower()
        _min_level_map = {
            "suspicious": SecurityLevel.SUSPICIOUS,
            "malicious":  SecurityLevel.MALICIOUS,
            "blocked":    SecurityLevel.BLOCKED,
        }
        from alerting import WebhookAlerter
        self.alerter = WebhookAlerter(
            webhook_url=_webhook_url,
            min_level=_min_level_map.get(_min_level_str, SecurityLevel.MALICIOUS),
            retry_count=int(_alert_cfg.get("retry_count", 3)),
        )

        # Auto-save stats
        self.stats_file = Path("logs/stats.pkl")
        self.load_stats()

    def format_bytes(self, bytes_count: int) -> str:
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"

    def format_duration(self, seconds: float) -> str:
        """Format duration to human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        elif seconds < 86400:
            return f"{seconds/3600:.1f}h"
        else:
            return f"{seconds/86400:.1f}d"

    def get_status_color(self, status_code: Optional[int]) -> str:
        """Get color for HTTP status code"""
        if not status_code:
            return "white"
        if 200 <= status_code < 300:
            return "green"
        elif 300 <= status_code < 400:
            return "yellow"
        elif 400 <= status_code < 500:
            return "orange1"
        else:
            return "red"

    def get_security_color(self, level: SecurityLevel) -> str:
        """Get color for security level"""
        colors = {
            SecurityLevel.SAFE: "green",
            SecurityLevel.SUSPICIOUS: "yellow",
            SecurityLevel.MALICIOUS: "red",
            SecurityLevel.BLOCKED: "red bold"
        }
        return colors.get(level, "white")

    def _check_client_ip(self, client_ip: str) -> bool:
        """Return True if the client IP is permitted to use the proxy.

        If an allowlist is configured only IPs in it are allowed.
        Otherwise the denylist is checked — IPs in it are rejected.
        """
        import ipaddress as _ip
        try:
            ip_obj = _ip.ip_address(client_ip)
        except ValueError:
            return True  # can't parse, let through

        if self._client_allowlist:
            return any(ip_obj in net for net in self._client_allowlist)
        if self._client_denylist:
            return not any(ip_obj in net for net in self._client_denylist)
        return True

    def _check_proxy_auth(self, headers_raw: str) -> bool:
        """Return True if auth is disabled or the supplied credentials are valid."""
        if not self._auth_user:
            return True
        import base64 as _b64
        for line in headers_raw.split("\r\n"):
            if line.lower().startswith("proxy-authorization:"):
                _, _, value = line.partition(":")
                value = value.strip()
                if value.lower().startswith("basic "):
                    try:
                        decoded = _b64.b64decode(value[6:]).decode("utf-8", errors="replace")
                        user, _, pw = decoded.partition(":")
                        return user == self._auth_user and pw == self._auth_pass
                    except Exception:
                        return False
        return False

    def log_event(self, metrics: ConnectionMetrics):
        """Log connection metrics"""
        self.stats.total_requests += 1

        if metrics.is_https:
            self.stats.https_requests += 1
        else:
            self.stats.http_requests += 1

        if metrics.error:
            self.stats.total_errors += 1

        if metrics.body_bytes:
            self.stats.total_bytes_received += metrics.body_bytes

        if metrics.status_code:
            self.stats.status_codes[metrics.status_code] += 1

        if metrics.method:
            self.stats.methods[metrics.method] += 1

        if metrics.content_type:
            self.stats.content_types[metrics.content_type] += 1

        # Cache tracking only applies to HTTP requests (CONNECT tunnels can't be cached)
        if metrics.type == "HTTP":
            if metrics.cached:
                self.stats.cache_hits += 1
            else:
                self.stats.cache_misses += 1

        if metrics.client_ip:
            self.stats.unique_clients.add(metrics.client_ip)
            self.stats.client_requests[metrics.client_ip] += 1

        if metrics.geo_location:
            self.stats.geo_stats[metrics.geo_location.country] += 1

        domain = metrics.host
        domain_stat = self.stats.domain_stats[domain]
        domain_stat['requests'] += 1
        domain_stat['last_seen'] = datetime.now().isoformat()

        if metrics.method:
            domain_stat['methods'][metrics.method] += 1
        if metrics.status_code:
            domain_stat['status_codes'][metrics.status_code] += 1
        if metrics.error:
            domain_stat['errors'] += 1
        if metrics.body_bytes:
            domain_stat['bytes'] += metrics.body_bytes
        if metrics.response_time_ms:
            old_avg = domain_stat['avg_time']
            n = domain_stat['requests']
            domain_stat['avg_time'] = (old_avg * (n - 1) + metrics.response_time_ms) / n

        if metrics.dns.dns_time_ms:
            self.stats.dns_times.append(metrics.dns.dns_time_ms)
        if metrics.tcp_connect_ms:
            self.stats.tcp_times.append(metrics.tcp_connect_ms)
        # For CONNECT tunnels, tcp_connect_ms is the meaningful "response time"
        rt = metrics.response_time_ms if metrics.type == "HTTP" else metrics.tcp_connect_ms
        if rt:
            self.stats.response_times.append(rt)

        hour = datetime.now().hour
        if metrics.body_bytes:
            self.stats.hourly_bandwidth[hour] += metrics.body_bytes

        self.stats.recent_requests.append(metrics)

        # Push a line to the live log pane
        ts  = datetime.now().strftime("%H:%M:%S")
        sec = metrics.security_level.value
        method = metrics.method or "CONN"
        status = str(metrics.status_code) if metrics.status_code else "-"
        size   = f" {metrics.body_bytes}B" if metrics.body_bytes else ""
        err    = f" ERR:{metrics.error}" if metrics.error else ""
        line = (ts, sec, f"{method:6} {metrics.host}:{metrics.port}  {status}{size}{err}  [{metrics.client_ip}]")
        self.stats.log_lines.append(line)
        self.stats.log_total += 1
        if len(self.stats.log_lines) > 1000:
            self.stats.log_lines = self.stats.log_lines[-500:]

        # Structured access log — one compact line per event
        geo_str   = ""
        if metrics.geo_location:
            g = metrics.geo_location
            geo_str = f" geo={g.country}/{g.city}"
        dns_ms    = f" dns={metrics.dns.dns_time_ms:.1f}ms" if (metrics.dns and metrics.dns.dns_time_ms) else ""
        tcp_ms    = f" tcp={metrics.tcp_connect_ms:.1f}ms" if metrics.tcp_connect_ms else ""
        rt_str    = f" resp={metrics.response_time_ms:.1f}ms" if metrics.response_time_ms else ""
        size_str  = f" {metrics.body_bytes}B" if metrics.body_bytes else ""
        cache_str = " CACHED" if metrics.cached else ""
        err_str   = f" ERR[{metrics.error}]" if metrics.error else ""
        self.access_log.info(
            f"{metrics.type:7} {metrics.client_ip:<15} → {metrics.host}:{metrics.port}"
            f"  {method:7} {status:>3}{size_str}"
            f"  {metrics.security_level.value.upper():<10}"
            f"{dns_ms}{tcp_ms}{rt_str}{cache_str}{geo_str}{err_str}"
        )

        asyncio.create_task(self.db.log_request(metrics))

    async def resolve_host(self, host: str) -> DNSInfo:
        """Resolve hostname to IP addresses with caching"""
        if host in self.dns_cache:
            info, timestamp = self.dns_cache[host]
            if time.time() - timestamp < self.dns_cache_ttl:
                info.cached = True
                return info

        start = time.time()
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_UNSPEC),
                timeout=5.0
            )
            addresses = list(set(info[4][0] for info in infos))
            end = time.time()

            is_ipv6 = any(':' in addr for addr in addresses)

            dns_info = DNSInfo(
                addresses=addresses,
                dns_time_ms=(end - start) * 1000,
                is_ipv6=is_ipv6,
                cached=False
            )

            self.dns_cache[host] = (dns_info, time.time())

            return dns_info

        except asyncio.TimeoutError:
            raise Exception(f"DNS resolution timeout for {host}")
        except socket.gaierror as e:
            raise Exception(f"DNS resolution failed for {host}: {e}")

    async def pipe_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        buffer_size: int = BUFFER_SIZE,
        throttle: bool = False,
        client_ip: str = "",
    ) -> int:
        """Pipe data between streams.

        Drains the write buffer lazily (only when it grows large) rather than
        after every chunk.  This cuts syscall overhead dramatically for large
        transfers and fast sites while still providing backpressure.
        """
        total_bytes = 0
        _drain_threshold = buffer_size * 8  # ~1 MB before we pause to drain
        try:
            while True:
                data = await reader.read(buffer_size)
                if not data:
                    break

                writer.write(data)
                total_bytes += len(data)

                if throttle and self.bandwidth_limit > 0:
                    await asyncio.sleep(len(data) / self.bandwidth_limit)
                elif throttle and client_ip:
                    _bw = self.bw_policy.get_limit(client_ip)
                    if _bw > 0:
                        await asyncio.sleep(len(data) / _bw)
                    else:
                        # Only drain when the write buffer is getting large
                        try:
                            if writer.transport.get_write_buffer_size() > _drain_threshold:
                                await writer.drain()
                        except AttributeError:
                            pass  # transport doesn't expose buffer size — skip
                else:
                    # Only drain when the write buffer is getting large
                    try:
                        if writer.transport.get_write_buffer_size() > _drain_threshold:
                            await writer.drain()
                    except AttributeError:
                        pass  # transport doesn't expose buffer size — skip

        except (ConnectionResetError, BrokenPipeError) as e:
            self.logger.debug(f"Connection closed during pipe: {e}")
        except Exception as e:
            self.logger.error(f"Error in pipe_stream: {e}")

        # Flush whatever is left in the write buffer
        try:
            await writer.drain()
        except Exception:
            pass
        return total_bytes

    @asynccontextmanager
    async def managed_connection(self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT, use_ssl: bool = False):
        """Context manager for remote connections with timeout and optional SSL.

        When upstream_proxy is configured, connections are tunnelled through it
        via HTTP CONNECT (for SSL) or direct absolute-URI requests (for plain HTTP).
        """
        reader = None
        writer = None
        ssl_time = 0.0

        try:
            ssl_start = time.time()

            # 256 KB StreamReader buffer — default 64 KB stalls on fast heavy sites
            _limit = 256 * 1024

            if self._upstream_host:
                # ── Route through upstream proxy ──────────────────────────────
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self._upstream_host, self._upstream_port, limit=_limit
                    ),
                    timeout=timeout,
                )
                if use_ssl:
                    # Tunnel via CONNECT
                    writer.write(
                        f"CONNECT {host}:{port} HTTP/1.1\r\n"
                        f"Host: {host}:{port}\r\n\r\n".encode()
                    )
                    await writer.drain()
                    resp_line = await asyncio.wait_for(
                        reader.readuntil(b"\r\n"), timeout=timeout
                    )
                    if b"200" not in resp_line:
                        raise ConnectionError(
                            f"Upstream proxy CONNECT failed: {resp_line.strip()}"
                        )
                    # Drain the rest of upstream proxy headers
                    while True:
                        hline = await asyncio.wait_for(
                            reader.readuntil(b"\r\n"), timeout=timeout
                        )
                        if hline == b"\r\n":
                            break
                    # Upgrade to SSL over the tunnel
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = True
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                    transport = writer.transport
                    loop = asyncio.get_event_loop()
                    new_transport = await loop.start_tls(
                        transport, ssl_context, server_hostname=host
                    )
                    reader._transport = new_transport  # type: ignore[attr-defined]
                    writer._transport = new_transport  # type: ignore[attr-defined]
            elif use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context,
                                           server_hostname=host, limit=_limit),
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, limit=_limit),
                    timeout=timeout
                )

            # TCP_NODELAY — reduce latency for interactive/small-packet traffic
            sock = writer.get_extra_info("socket")
            if sock is not None:
                try:
                    import socket as _socket
                    sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            ssl_end = time.time()
            ssl_time = (ssl_end - ssl_start) * 1000

            if use_ssl and ssl_time > 0:
                self.stats.ssl_times.append(ssl_time)

            yield reader, writer
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    self.logger.debug(f"Error closing connection: {e}")

    async def handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
        client_ip: str
    ):
        """Handle HTTPS CONNECT method"""
        self.stats.active_connections += 1
        self.stats.peak_connections = max(self.stats.peak_connections, self.stats.active_connections)

        metrics = ConnectionMetrics(
            type="CONNECT",
            host=target_host,
            port=target_port,
            dns=DNSInfo(addresses=[], dns_time_ms=0),
            tcp_connect_ms=0,
            timestamp=datetime.utcnow().isoformat(),
            client_ip=client_ip,
            is_https=True
        )

        try:
            # Security checks
            sec_level, sec_reason = self.security.analyze_url(f"https://{target_host}", target_host)
            metrics.security_level = sec_level

            if sec_level == SecurityLevel.MALICIOUS:
                raise Exception(f"Malicious domain blocked: {sec_reason}")

            if target_host in self.stats.blocked_domains:
                raise Exception(f"Domain blocked: {target_host}")

            if self.stats.whitelist_mode and target_host not in self.stats.allowed_domains:
                raise Exception(f"Domain not in whitelist: {target_host}")

            if not self.security.check_rate_limit(client_ip):
                raise Exception(f"Rate limit exceeded for {client_ip}")

            # Resolve DNS
            metrics.dns = await self.resolve_host(target_host)

            # Geo-location
            metrics.geo_location = await self.geoip.resolve(client_ip)

            # Connect to target
            tcp_start = time.time()
            async with self.managed_connection(target_host, target_port,
                                               timeout=self._connect_timeout) as (remote_reader, remote_writer):
                tcp_end = time.time()
                metrics.tcp_connect_ms = (tcp_end - tcp_start) * 1000

                # Send success response
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()

                self.log_event(metrics)
                tunnel_start = time.time()

                # Detect WebSocket upgrade by peeking at the first bytes from client
                try:
                    _first_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=2)
                except asyncio.TimeoutError:
                    _first_chunk = b""
                if _first_chunk:
                    _decoded = _first_chunk.decode(errors="ignore").lower()
                    if "upgrade: websocket" in _decoded:
                        self.logger.info(
                            f"WebSocket detected: {client_ip} -> {target_host}:{target_port}"
                        )
                        asyncio.create_task(self.db.log_connection(
                            client_ip, target_host, target_port, 0, 0, 0,
                        ))
                    # Forward the peeked chunk to remote
                    remote_writer.write(_first_chunk)
                    await remote_writer.drain()

                # Bidirectional pipe
                results = await asyncio.gather(
                    self.pipe_stream(client_reader, remote_writer, throttle=True, client_ip=client_ip),
                    self.pipe_stream(remote_reader, client_writer, throttle=True, client_ip=client_ip),
                    return_exceptions=True
                )

                bytes_sent     = results[0] if isinstance(results[0], int) else 0
                bytes_received = results[1] if isinstance(results[1], int) else 0
                self.stats.total_bytes_sent     += bytes_sent
                self.stats.total_bytes_received += bytes_received

                tunnel_ms = (time.time() - tunnel_start) * 1000
                total_bytes = bytes_sent + bytes_received
                self.logger.debug(
                    f"TUNNEL closed {target_host}:{target_port} "
                    f"duration={tunnel_ms:.0f}ms ↑{bytes_sent}B ↓{bytes_received}B"
                )
                asyncio.create_task(self.db.log_connection(
                    client_ip, target_host, target_port,
                    tunnel_ms, bytes_sent, bytes_received,
                ))

        except Exception as e:
            error_msg = str(e)
            metrics.error = error_msg
            _is_block = any(kw in error_msg.lower() for kw in
                            ("blocked", "malicious", "whitelist", "rate limit"))
            if _is_block:
                metrics.security_level = SecurityLevel.BLOCKED
            self.log_event(metrics)

            from database import classify_error
            err_type = classify_error(error_msg)
            self.error_log.warning(
                f"CONNECT {target_host}:{target_port} [{err_type}] {error_msg}"
            )

            if _is_block:
                self.stats.threats_blocked += 1
                threat = SecurityThreat(
                    level=SecurityLevel.BLOCKED,
                    reason=error_msg,
                    timestamp=datetime.utcnow().isoformat(),
                    ip=client_ip,
                    host=target_host
                )
                self.stats.security_threats.append(threat)
                self.stats.malicious_ips.add(client_ip)
                self.sec_log.warning(
                    f"BLOCKED {client_ip} → {target_host}:{target_port}  reason={error_msg}"
                )
                asyncio.create_task(self.db.log_threat(threat))
                asyncio.create_task(self.alerter.send(threat))
                self.add_alert("SECURITY", f"Blocked: {target_host} from {client_ip}")

            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
        finally:
            self.stats.active_connections -= 1

    async def handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        first_line: str,
        headers_raw: str,
        client_ip: str
    ):
        """Handle regular HTTP requests with caching"""
        self.stats.active_connections += 1
        self.stats.peak_connections = max(self.stats.peak_connections, self.stats.active_connections)

        try:
            method, full_url, version = first_line.split()
        except ValueError:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            self.stats.active_connections -= 1
            return

        parsed = urlsplit(full_url)
        host = parsed.hostname

        if not host:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            self.stats.active_connections -= 1
            return

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Parse headers
        headers_dict = {}
        user_agent = None
        for line in headers_raw.split("\r\n"):
            if ": " in line:
                key, value = line.split(": ", 1)
                headers_dict[key.lower()] = value
                if key.lower() == "user-agent":
                    user_agent = value

        is_https = parsed.scheme == "https"

        metrics = ConnectionMetrics(
            type="HTTP",
            host=host,
            port=port,
            method=method,
            url=full_url,
            dns=DNSInfo(addresses=[], dns_time_ms=0),
            tcp_connect_ms=0,
            timestamp=datetime.utcnow().isoformat(),
            client_ip=client_ip,
            user_agent=user_agent,
            request_headers=headers_dict,
            is_https=is_https
        )

        try:
            # Security checks
            sec_level, sec_reason = self.security.analyze_url(full_url, host)
            header_sec_level, header_sec_reason = self.security.analyze_headers(headers_dict)

            if header_sec_level.value > sec_level.value:
                sec_level = header_sec_level
                sec_reason = header_sec_reason

            metrics.security_level = sec_level

            if sec_level == SecurityLevel.MALICIOUS:
                raise Exception(f"Malicious request blocked: {sec_reason}")

            if self.filter_mgr.is_blocked(host) and not self.filter_mgr.is_bypassed(host):
                raise Exception(f"Domain blocked: {host}")

            if self.stats.whitelist_mode and not self.filter_mgr.is_bypassed(host) \
                    and host not in self.stats.allowed_domains:
                raise Exception(f"Domain not in whitelist: {host}")

            if not self.security.check_rate_limit(client_ip):
                raise Exception(f"Rate limit exceeded for {client_ip}")

            # Check cache
            cache_entry = await self.cache.get(method, full_url, headers_dict)
            if cache_entry:
                metrics.cached = True
                metrics.status_code = cache_entry.status_code
                metrics.body_bytes = cache_entry.size
                metrics.response_time_ms = 0

                _STATUS_TEXT = {
                    200: "OK", 201: "Created", 204: "No Content",
                    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
                    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                    404: "Not Found", 405: "Method Not Allowed", 410: "Gone",
                    500: "Internal Server Error", 502: "Bad Gateway",
                }
                status_text = _STATUS_TEXT.get(cache_entry.status_code, "OK")
                _HOP = frozenset({"transfer-encoding", "connection", "keep-alive",
                                  "proxy-connection", "te", "trailer", "upgrade"})

                client_writer.write(
                    f"HTTP/1.1 {cache_entry.status_code} {status_text}\r\n".encode()
                )
                client_writer.write(b"X-Cache: HIT\r\n")
                client_writer.write(
                    f"Content-Length: {len(cache_entry.body)}\r\n".encode()
                )
                for k, v in cache_entry.headers.items():
                    if k.lower() not in _HOP and k.lower() != "content-length":
                        client_writer.write(f"{k}: {v}\r\n".encode())
                client_writer.write(b"\r\n")
                client_writer.write(cache_entry.body)
                await client_writer.drain()

                self.log_event(metrics)
                self.stats.active_connections -= 1
                return

            # Resolve DNS
            metrics.dns = await self.resolve_host(host)

            # Geo-location
            metrics.geo_location = await self.geoip.resolve(client_ip)

            # Connect to target
            tcp_start = time.time()
            async with self.managed_connection(host, port, use_ssl=is_https) as (remote_reader, remote_writer):
                tcp_end = time.time()
                metrics.tcp_connect_ms = (tcp_end - tcp_start) * 1000

                # Reconstruct request — strip proxy/hop-by-hop headers, force HTTP/1.1
                # with Connection: close so the server terminates after the response.
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query

                _REQ_HOP = frozenset({
                    "proxy-connection", "keep-alive", "proxy-authenticate",
                    "proxy-authorization", "te", "trailers", "upgrade", "connection",
                })
                # Build a dict of forwarded headers so HeaderRewriter can manipulate them
                _fwd_dict = {}
                for line in headers_raw.split("\r\n"):
                    if not line or ":" not in line:
                        continue
                    k, _, v = line.partition(":")
                    if k.lower() not in _REQ_HOP:
                        _fwd_dict[k.strip()] = v.strip()
                _fwd_dict["Connection"] = "close"

                # Apply request rewrite rules
                _fwd_dict = self.header_rewriter.apply_request(_fwd_dict)

                new_request = f"{method} {path} HTTP/1.1\r\n"
                new_request += "\r\n".join(f"{k}: {v}" for k, v in _fwd_dict.items()) + "\r\n\r\n"

                remote_writer.write(new_request.encode())
                await remote_writer.drain()

                # ── Forward request body (POST/PUT/PATCH etc.) ────────────────
                _req_cl = headers_dict.get("content-length", "").strip()
                _req_te = headers_dict.get("transfer-encoding", "").lower()
                if _req_cl:
                    try:
                        _body_remaining = int(_req_cl)
                        while _body_remaining > 0:
                            _chunk = await asyncio.wait_for(
                                client_reader.read(min(_body_remaining, BUFFER_SIZE)),
                                timeout=self._body_timeout,
                            )
                            if not _chunk:
                                break
                            remote_writer.write(_chunk)
                            _body_remaining -= len(_chunk)
                        await remote_writer.drain()
                    except (ValueError, asyncio.TimeoutError):
                        pass
                elif "chunked" in _req_te:
                    try:
                        while True:
                            _size_line = await asyncio.wait_for(
                                client_reader.readuntil(b"\r\n"),
                                timeout=self._body_timeout,
                            )
                            remote_writer.write(_size_line)
                            _chunk_size = int(_size_line.strip().split(b";")[0], 16)
                            if _chunk_size == 0:
                                # Trailing headers + final CRLF
                                while True:
                                    _trailer = await asyncio.wait_for(
                                        client_reader.readuntil(b"\r\n"),
                                        timeout=self._body_timeout,
                                    )
                                    remote_writer.write(_trailer)
                                    if _trailer == b"\r\n":
                                        break
                                break
                            _cdata = await asyncio.wait_for(
                                client_reader.readexactly(_chunk_size + 2),
                                timeout=self._body_timeout,
                            )
                            remote_writer.write(_cdata)
                        await remote_writer.drain()
                    except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                        pass

                # Stream response back to client
                response_start = time.time()
                body_parts = []
                body_size = 0
                status_code = 0
                response_headers = {}

                # Read and forward status line
                status_line = await remote_reader.readuntil(b"\r\n")
                client_writer.write(status_line)

                try:
                    parts = status_line.decode(errors="ignore").split()
                    if len(parts) >= 2:
                        status_code = int(parts[1])
                except Exception:
                    pass

                # Read all response headers, apply rewrite rules, forward
                _raw_resp_hdrs: list[bytes] = []
                while True:
                    line = await remote_reader.readuntil(b"\r\n")
                    if line == b"\r\n":
                        break
                    _raw_resp_hdrs.append(line)

                _resp_dict: dict[str, str] = {}
                for _rl in _raw_resp_hdrs:
                    _header_line = _rl.decode(errors="ignore").strip()
                    if ": " in _header_line:
                        _rk, _rv = _header_line.split(": ", 1)
                        _resp_dict[_rk] = _rv
                        response_headers[_rk.lower()] = _rv

                # Apply response rewrite rules
                _resp_dict = self.header_rewriter.apply_response(_resp_dict)

                # Re-build response_headers from rewritten dict
                response_headers = {k.lower(): v for k, v in _resp_dict.items()}

                # Forward rewritten headers to client
                for _rk, _rv in _resp_dict.items():
                    client_writer.write(f"{_rk}: {_rv}\r\n".encode())
                client_writer.write(b"\r\n")

                await client_writer.drain()

                # ── Body streaming ────────────────────────────────────────────
                # Strategy depends on how the server signals body length:
                #   Content-Length  → read exactly N bytes (most reliable)
                #   Transfer-Encoding: chunked → parse chunk frames
                #   neither (Connection: close) → read until EOF
                #
                # Buffer up to _CACHE_MAX bytes for caching and _SAMPLE_MAX for
                # threat-inspection; stream everything else directly.
                _CACHE_MAX  = 512 * 1024
                _SAMPLE_MAX = 32  * 1024
                _DRAIN_HWM  = BUFFER_SIZE * 4
                _btimeout   = self._body_timeout

                will_cache = (
                    method in ("GET", "HEAD")
                    and status_code == 200
                    and self.cache._is_cacheable(method, status_code,
                                                 response_headers, headers_dict)
                )

                body_parts: list = []
                body_size   = 0
                sampled     = 0

                def _store(data: bytes):
                    """Accumulate data for cache / inspection; do NOT write to socket."""
                    nonlocal body_size, sampled
                    body_size += len(data)
                    if will_cache and body_size <= _CACHE_MAX:
                        body_parts.append(data)
                    elif sampled < _SAMPLE_MAX:
                        body_parts.append(data)
                        sampled += len(data)

                async def _send(data: bytes):
                    """Write to client and drain lazily."""
                    client_writer.write(data)
                    try:
                        if client_writer.transport.get_write_buffer_size() > _DRAIN_HWM:
                            await client_writer.drain()
                    except (AttributeError, Exception):
                        pass

                te     = response_headers.get("transfer-encoding", "").lower()
                cl_str = response_headers.get("content-length", "").strip()

                if method == "HEAD" or status_code in (204, 304):
                    # No body for HEAD / 204 / 304
                    pass

                elif "chunked" in te:
                    # ── Chunked transfer encoding ─────────────────────────────
                    while True:
                        try:
                            size_line = await asyncio.wait_for(
                                remote_reader.readuntil(b"\r\n"), timeout=_btimeout
                            )
                        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                            break
                        await _send(size_line)
                        try:
                            chunk_size = int(size_line.strip().split(b";")[0], 16)
                        except ValueError:
                            break
                        if chunk_size == 0:
                            # Terminal chunk — forward optional trailers then empty CRLF
                            while True:
                                try:
                                    trailer = await asyncio.wait_for(
                                        remote_reader.readuntil(b"\r\n"), timeout=_btimeout
                                    )
                                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                                    break
                                await _send(trailer)
                                if trailer == b"\r\n":
                                    break
                            break
                        # Read chunk data + trailing CRLF
                        try:
                            chunk_data = await asyncio.wait_for(
                                remote_reader.readexactly(chunk_size + 2), timeout=_btimeout
                            )
                        except asyncio.TimeoutError:
                            break
                        except asyncio.IncompleteReadError as exc:
                            if exc.partial:
                                _store(exc.partial)
                                await _send(exc.partial)
                            break
                        _store(chunk_data[:chunk_size])  # store actual data only
                        await _send(chunk_data)          # forward data + CRLF framing

                elif cl_str:
                    # ── Content-Length ────────────────────────────────────────
                    try:
                        remaining = int(cl_str)
                    except ValueError:
                        remaining = -1

                    while remaining > 0:
                        try:
                            data = await asyncio.wait_for(
                                remote_reader.read(min(BUFFER_SIZE, remaining)),
                                timeout=_btimeout,
                            )
                        except asyncio.TimeoutError:
                            break
                        if not data:
                            break
                        remaining -= len(data)
                        _store(data)
                        await _send(data)

                else:
                    # ── Read until server closes connection ───────────────────
                    # (safe because we sent Connection: close)
                    while True:
                        try:
                            data = await asyncio.wait_for(
                                remote_reader.read(BUFFER_SIZE), timeout=_btimeout
                            )
                        except asyncio.TimeoutError:
                            break
                        if not data:
                            break
                        _store(data)
                        await _send(data)

                try:
                    await client_writer.drain()
                except Exception:
                    pass

                response_end = time.time()

                metrics.status_code = status_code
                metrics.response_time_ms = (response_end - response_start) * 1000
                metrics.body_bytes = body_size
                metrics.response_headers = response_headers

                # Analyze the collected sample (capped at _SAMPLE_MAX)
                sample = b"".join(body_parts)
                analysis = self.inspector.analyze_response(
                    status_code, response_headers, sample[:_SAMPLE_MAX]
                )
                metrics.content_type = analysis["content_type"]
                metrics.compressed   = analysis["compressed"]

                # Check for threats in response
                if analysis["threats"]:
                    threat = SecurityThreat(
                        level=SecurityLevel.SUSPICIOUS,
                        reason="Suspicious content detected",
                        timestamp=datetime.utcnow().isoformat(),
                        ip=client_ip,
                        host=host,
                        patterns=analysis["threats"]
                    )
                    self.stats.security_threats.append(threat)
                    self.sec_log.warning(
                        f"SUSPICIOUS {client_ip} → {host}  patterns={analysis['threats'][:2]}"
                    )
                    asyncio.create_task(self.db.log_threat(threat))
                    asyncio.create_task(self.alerter.send(threat))

                # Cache if we collected the full body within the size limit
                if will_cache and body_size <= _CACHE_MAX:
                    await self.cache.set(
                        method, full_url, headers_dict,
                        status_code, response_headers, sample
                    )

                self.stats.total_bytes_sent += len(new_request.encode())

                self.log_event(metrics)

        except Exception as e:
            error_msg = str(e)
            metrics.error = error_msg
            _is_block = any(kw in error_msg.lower() for kw in
                            ("blocked", "malicious", "whitelist", "rate limit"))
            if _is_block:
                metrics.security_level = SecurityLevel.BLOCKED
            self.log_event(metrics)

            from database import classify_error
            err_type = classify_error(error_msg)
            self.error_log.warning(
                f"HTTP  {method} {full_url} [{err_type}] {error_msg}"
            )

            if _is_block:
                self.stats.threats_blocked += 1
                threat = SecurityThreat(
                    level=SecurityLevel.BLOCKED,
                    reason=error_msg,
                    timestamp=datetime.utcnow().isoformat(),
                    ip=client_ip,
                    host=host
                )
                self.stats.security_threats.append(threat)
                self.stats.malicious_ips.add(client_ip)
                self.sec_log.warning(
                    f"BLOCKED {client_ip} → {host}:{port}  method={method}  reason={error_msg}"
                )
                asyncio.create_task(self.db.log_threat(threat))
                asyncio.create_task(self.alerter.send(threat))
                self.add_alert("SECURITY", f"Blocked: {host} from {client_ip}")

            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
        finally:
            self.stats.active_connections -= 1

    # ──────────────────────────────────────────────────────────────────────────
    # SOCKS5 handler
    # ──────────────────────────────────────────────────────────────────────────
    async def _handle_socks5(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        conn_start: float,
    ):
        """Minimal SOCKS5 CONNECT handler (no-auth)."""
        try:
            # Greeting: client already sent 0x05; read nmethods + methods
            nmethods_b = await asyncio.wait_for(reader.readexactly(1), timeout=self._read_timeout)
            nmethods = nmethods_b[0]
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=self._read_timeout)
            # Accept with no-auth (0x00)
            writer.write(b"\x05\x00")
            await writer.drain()

            # Request: VER CMD RSV ATYP ...
            req_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=self._read_timeout)
            ver, cmd, _, atyp = req_hdr
            if ver != 5 or cmd != 1:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)  # command not supported
                await writer.drain()
                return

            if atyp == 0x01:  # IPv4
                raw = await asyncio.wait_for(reader.readexactly(4), timeout=self._read_timeout)
                import socket as _socket
                host = _socket.inet_ntoa(raw)
            elif atyp == 0x03:  # Domain name
                n = (await asyncio.wait_for(reader.readexactly(1), timeout=self._read_timeout))[0]
                host = (await asyncio.wait_for(reader.readexactly(n), timeout=self._read_timeout)).decode()
            elif atyp == 0x04:  # IPv6
                raw = await asyncio.wait_for(reader.readexactly(16), timeout=self._read_timeout)
                import socket as _socket
                host = _socket.inet_ntop(_socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)  # address type not supported
                await writer.drain()
                return

            port_b = await asyncio.wait_for(reader.readexactly(2), timeout=self._read_timeout)
            port = int.from_bytes(port_b, "big")

            # Check filter
            if self.filter_mgr.is_blocked(host) and not self.filter_mgr.is_bypassed(host):
                writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)  # connection not allowed
                await writer.drain()
                self.logger.info(f"SOCKS5 blocked {host}:{port} from {client_ip}")
                return

            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self._connect_timeout,
                )
            except Exception as exc:
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
                await writer.drain()
                self.logger.warning(f"SOCKS5 connect failed {host}:{port}: {exc}")
                return

            # Success reply
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            self.logger.info(f"SOCKS5 CONNECT {client_ip} -> {host}:{port}")
            self.stats.active_connections += 1
            try:
                await asyncio.gather(
                    self.pipe_stream(reader, remote_writer, throttle=True, client_ip=client_ip),
                    self.pipe_stream(remote_reader, writer, throttle=True, client_ip=client_ip),
                    return_exceptions=True,
                )
            finally:
                self.stats.active_connections -= 1
                try:
                    remote_writer.close()
                except Exception:
                    pass
        except Exception as exc:
            self.error_log.debug(f"SOCKS5 error from {client_ip}: {exc}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle incoming client connection"""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else "unknown"

        # Enforce max-connections semaphore — don't block, just drop if full
        if not self._conn_sem._value:
            self.error_log.warning(f"Max connections reached, dropping {client_ip}")
            try:
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
            return

        async with self._conn_sem:
            await self._handle_client_inner(reader, writer, client_ip)

    async def _handle_client_inner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
    ):
        """Inner handler — called under the semaphore."""
        conn_start = time.time()
        self.logger.debug(f"New connection from {client_ip}")

        # ── IP allow/deny list ─────────────────────────────────────────────
        if not self._check_client_ip(client_ip):
            self.sec_log.warning(f"REJECTED denied IP {client_ip}")
            try:
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
            return

        if client_ip in self.stats.malicious_ips:
            self.sec_log.warning(f"REJECTED known-malicious IP {client_ip}")
            self.error_log.warning(f"Rejected malicious IP {client_ip}")
            try:
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
            return

        try:
            # Peek at the first byte to detect SOCKS5 / SOCKS4
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=self._read_timeout)
            if first_byte == b"\x05":
                await self._handle_socks5(reader, writer, client_ip, conn_start)
                return
            if first_byte == b"\x04":
                writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")  # SOCKS4 reject
                await writer.drain()
                writer.close()
                return

            data = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self._read_timeout
            )
            data = first_byte + data  # prepend the already-read byte

            if len(data) > MAX_HEADER_SIZE:
                self.error_log.warning(f"Header too large from {client_ip} ({len(data)}B)")
                writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                await writer.drain()
                return

            header_text = data.decode(errors="ignore")
            lines = header_text.split("\r\n")

            if not lines:
                return

            first_line = lines[0]
            headers_raw = "\r\n".join(lines[1:])

            # ── Proxy authentication ──────────────────────────────────────────
            if not self._check_proxy_auth(headers_raw):
                try:
                    writer.write(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b"Proxy-Authenticate: Basic realm=\"JARVIS\"\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                except Exception:
                    pass
                return

            if first_line.startswith("CONNECT"):
                try:
                    _, target, _ = first_line.split()
                    host, port_str = target.rsplit(":", 1)
                    port = int(port_str)
                    await self.handle_connect(reader, writer, host, port, client_ip)
                except ValueError:
                    self.error_log.warning(f"Bad CONNECT line from {client_ip}: {first_line!r}")
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
            else:
                await self.handle_http(reader, writer, first_line, headers_raw, client_ip)

        except asyncio.TimeoutError:
            self.error_log.warning(f"Header read timeout from {client_ip} after {self._read_timeout}s")
        except asyncio.IncompleteReadError:
            self.logger.debug(f"Incomplete read from {client_ip}")
        except Exception as e:
            self.error_log.error(f"Unhandled error from {client_ip}: {e}")
            self.logger.debug(f"handle_client traceback", exc_info=True)
        finally:
            conn_ms = (time.time() - conn_start) * 1000
            self.logger.debug(f"Connection from {client_ip} closed after {conn_ms:.0f}ms")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def save_stats(self):
        """Save statistics and cache to disk atomically."""
        # ── stats ──
        tmp = self.stats_file.with_suffix(".tmp")
        try:
            # Don't persist instantaneous bps or display-only log buffer
            save_state = self.stats.__dict__.copy()
            save_state["current_upload_bps"]   = 0.0
            save_state["current_download_bps"] = 0.0
            save_state["log_lines"]  = []
            save_state["log_total"]  = 0
            save_state["active_connections"] = 0
            with open(tmp, 'wb') as f:
                pickle.dump(save_state, f, protocol=pickle.HIGHEST_PROTOCOL)
            tmp.replace(self.stats_file)          # atomic on POSIX
            self.logger.debug("Statistics saved")
        except Exception as e:
            self.logger.error(f"Error saving stats: {e}")
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass

        # ── cache ──
        cache_file = Path("logs/cache.pkl")
        tmp_cache  = cache_file.with_suffix(".tmp")
        try:
            # Only persist non-expired entries up to 500 items
            now = time.time()
            entries = {
                k: v for k, v in self.cache.cache.items()
                if time.time() - v.timestamp < self.cache.ttl
            }
            # Keep the 500 most-recently accessed
            if len(entries) > 500:
                entries = dict(
                    sorted(entries.items(), key=lambda x: x[1].last_access, reverse=True)[:500]
                )
            with open(tmp_cache, 'wb') as f:
                pickle.dump(entries, f, protocol=pickle.HIGHEST_PROTOCOL)
            tmp_cache.replace(cache_file)
            self.logger.debug(f"Cache saved ({len(entries)} entries)")
        except Exception as e:
            self.logger.error(f"Error saving cache: {e}")
            try:
                tmp_cache.unlink(missing_ok=True)
            except Exception:
                pass

    def load_stats(self):
        """Load statistics and cache from disk."""
        # ── stats ──
        try:
            if self.stats_file.exists() and self.stats_file.stat().st_size > 0:
                with open(self.stats_file, 'rb') as f:
                    saved = pickle.load(f)
                # Restore saved state into the existing (fresh) stats object
                if isinstance(saved, dict):
                    for k, v in saved.items():
                        if hasattr(self.stats, k):
                            setattr(self.stats, k, v)
                else:
                    # Old format — whole ProxyStats object
                    self.stats = saved
                # Always reset transient fields on load
                self.stats.active_connections  = 0
                self.stats.current_upload_bps  = 0.0
                self.stats.current_download_bps = 0.0
                self.stats.start_time          = time.time()
                self.stats.log_lines           = []
                self.stats.log_total           = 0
                self.logger.info("Statistics loaded")
        except Exception as e:
            self.logger.error(f"Error loading stats: {e}")

        # ── cache ──
        cache_file = Path("logs/cache.pkl")
        try:
            if cache_file.exists() and cache_file.stat().st_size > 0:
                with open(cache_file, 'rb') as f:
                    entries = pickle.load(f)
                # Filter out expired entries
                now = time.time()
                valid = {k: v for k, v in entries.items()
                         if now - v.timestamp < self.cache.ttl}
                self.cache.cache.update(valid)
                self.logger.info(f"Cache loaded ({len(valid)} valid entries)")
        except Exception as e:
            self.logger.error(f"Error loading cache: {e}")

    async def auto_save_stats(self):
        """Periodically save statistics every 60 seconds."""
        while self.running:
            await asyncio.sleep(60)
            self.save_stats()

    async def bandwidth_tracker_task(self):
        """Sample bytes sent/received every second; compute rolling bps; log when active."""
        last_sent = self.stats.total_bytes_sent
        last_recv = self.stats.total_bytes_received
        last_ts   = time.monotonic()
        while True:
            await asyncio.sleep(1.0)
            now  = time.monotonic()
            dt   = max(now - last_ts, 0.001)
            sent = self.stats.total_bytes_sent
            recv = self.stats.total_bytes_received
            up_bps = (sent - last_sent) / dt
            dn_bps = (recv - last_recv) / dt
            self.stats.current_upload_bps   = up_bps
            self.stats.current_download_bps = dn_bps
            self.stats.upload_bps_history.append(up_bps)
            self.stats.download_bps_history.append(dn_bps)
            last_sent, last_recv, last_ts = sent, recv, now
            if up_bps > 0 or dn_bps > 0:
                self.perf_log.debug(
                    f"BW  ↑{self.format_bytes(up_bps)}/s  ↓{self.format_bytes(dn_bps)}/s"
                    f"  total ↑{self.format_bytes(sent)}  ↓{self.format_bytes(recv)}"
                )

    async def perf_snapshot_task(self):
        """Log a performance snapshot every 60 seconds to the perf log and DB."""
        last_count = self.stats.total_requests
        while self.running:
            await asyncio.sleep(60)
            s = self.stats
            up = max(time.time() - s.start_time, 1)
            rpm = s.total_requests - last_count
            last_count = s.total_requests
            avg_resp   = sum(s.response_times) / len(s.response_times) if s.response_times else 0
            cache_tot  = s.cache_hits + s.cache_misses
            hit_rate   = s.cache_hits / cache_tot * 100 if cache_tot else 0
            total_bw   = s.total_bytes_sent + s.total_bytes_received
            bps        = total_bw / up
            err_rate   = s.total_errors / max(s.total_requests, 1) * 100

            self.perf_log.info(
                f"SNAPSHOT  reqs={s.total_requests:,}  rpm={rpm}  "
                f"active={s.active_connections}  avg_resp={avg_resp:.1f}ms  "
                f"cache={hit_rate:.1f}%  bw={bps:.0f}B/s  "
                f"err={err_rate:.1f}%  clients={len(s.unique_clients)}  "
                f"threats={s.threats_blocked}"
            )
            asyncio.create_task(self.db.log_perf_snapshot(
                total_requests      = s.total_requests,
                requests_this_minute= rpm,
                active_connections  = s.active_connections,
                avg_response_ms     = avg_resp,
                cache_hit_rate      = hit_rate,
                bytes_per_sec       = bps,
                error_rate          = err_rate,
                unique_clients      = len(s.unique_clients),
                threats_blocked     = s.threats_blocked,
            ))

    def add_alert(self, alert_type: str, message: str):
        """Add system alert"""
        self.alerts.append({
            'time': datetime.now().strftime("%H:%M:%S"),
            'type': alert_type,
            'message': message,
        })

    async def start(self):
        """Start the proxy server"""
        from tui import JARVISApp
        from web_ui import WebUIServer

        self.running = True
        save_task = asyncio.create_task(self.auto_save_stats())
        perf_task = asyncio.create_task(self.perf_snapshot_task())
        bw_task   = asyncio.create_task(self.bandwidth_tracker_task())

        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            reuse_address=True,
            reuse_port=True,
        )

        # Start web UI (accessible from any device on the LAN)
        _webui_port = cfg.get("web_ui", "port", 8890)
        webui = WebUIServer(self, self.host, _webui_port)
        self._webui_server = await webui.start()

        # Health check endpoint
        from health import HealthCheckServer
        _health_port = cfg.get("health", "port", 0)
        self._health_server = HealthCheckServer(self, _health_port)
        await self._health_server.start()

        # Ad-block list background sync
        _filter_cfg = cfg.load().get("filter", {})
        _sync_lists = _filter_cfg.get("sync_lists", [])
        _sync_hours = float(_filter_cfg.get("sync_interval_hours", 24))
        if _sync_lists:
            from blocklist_sync import sync_loop
            asyncio.create_task(sync_loop(
                interval_hours=_sync_hours,
                lists=_sync_lists,
                output_file=_filter_cfg.get("blocklist_file", "filters/blocklist.txt"),
            ))

        ssl_mode = "SSL Inspection ON" if self.enable_ssl_inspection else "CONNECT-only mode"
        self.add_alert("SYSTEM", f"J.A.R.V.I.S. Proxy started on {self.host}:{self.port} ({ssl_mode})")
        self.add_alert("SYSTEM", f"Web UI available at http://{self.host}:{_webui_port}")

        app = JARVISApp(self)

        async with self.server:
            try:
                serve_task = asyncio.create_task(self.server.serve_forever())
                await app.run_async()
                # TUI exited — stop the server
                self.running = False
                serve_task.cancel()
                try:
                    await serve_task
                except asyncio.CancelledError:
                    pass
            except (KeyboardInterrupt, asyncio.CancelledError):
                self.running = False
            finally:
                self._webui_server.close()
                await self._health_server.stop()
                save_task.cancel()
                perf_task.cancel()
                bw_task.cancel()
                for t in (save_task, perf_task, bw_task):
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass
                self.save_stats()
                await self.geoip.close()
                await self.alerter.close()
                try:
                    from har_export import export as _har_export
                    _har_export(self)
                except Exception as _e:
                    self.logger.warning(f"HAR export failed: {_e}")
                self.logger.info("J.A.R.V.I.S. shut down cleanly")

    def add_blocked_domain(self, domain: str):
        """Add domain to blocklist"""
        self.stats.blocked_domains.add(domain)
        self.logger.info(f"Blocked domain: {domain}")
        self.add_alert("SECURITY", f"Blocked domain: {domain}")

    def remove_blocked_domain(self, domain: str):
        """Remove domain from blocklist"""
        self.stats.blocked_domains.discard(domain)
        self.logger.info(f"Unblocked domain: {domain}")
        self.add_alert("SECURITY", f"Unblocked domain: {domain}")

    def enable_whitelist_mode(self):
        """Enable whitelist mode"""
        self.stats.whitelist_mode = True
        self.add_alert("SECURITY", "Whitelist mode enabled")

    def disable_whitelist_mode(self):
        """Disable whitelist mode"""
        self.stats.whitelist_mode = False
        self.add_alert("SECURITY", "Whitelist mode disabled")


