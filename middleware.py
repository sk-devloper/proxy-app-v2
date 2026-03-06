"""Request/response middleware pipeline for J.A.R.V.I.S. Proxy.

Encapsulates the security-check, filter, and anomaly-detection logic that
was previously inlined inside handle_http / handle_connect.  Each check
function raises an Exception with a descriptive message to signal a block,
so the calling handler can write the appropriate error response and log the
event without any conditional branching on the return value.

Usage::

    from middleware import run_request_checks

    # In handle_http / handle_connect:
    await run_request_checks(proxy, client_ip, host, url, method, headers)
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from proxy import JARVISProxy

log = logging.getLogger("JARVIS.middleware")


async def run_request_checks(
    proxy: "JARVISProxy",
    client_ip: str,
    host: str,
    url: str,
    method: str,
    headers: Dict[str, str],
) -> None:
    """Run all pre-forward security and filter checks for an HTTP request.

    Raises ``Exception`` with a human-readable reason if the request should
    be blocked.  Returns normally if the request may proceed.

    Checks (in order):
      1. URL and header security analysis (XSS, SQLi, attack tools)
      2. Domain blocklist / whitelist
      3. Category filter
      4. Rate limiting
      5. Anomaly detection (non-blocking alert, never raises)
    """
    from models import SecurityLevel

    # ── 1. Security analysis ─────────────────────────────────────────────────
    sec_level, sec_reason = proxy.security.analyze_url(url, host)
    hdr_level,  hdr_reason = proxy.security.analyze_headers(headers)

    if hdr_level.value > sec_level.value:
        sec_level  = hdr_level
        sec_reason = hdr_reason

    if sec_level == SecurityLevel.MALICIOUS:
        raise Exception(f"Malicious request blocked: {sec_reason}")

    # ── 2. Domain filter ─────────────────────────────────────────────────────
    if proxy.filter_mgr.is_blocked(host) and not proxy.filter_mgr.is_bypassed(host):
        raise Exception(f"Domain blocked: {host}")

    if proxy.stats.whitelist_mode and not proxy.filter_mgr.is_bypassed(host) \
            and host not in proxy.stats.allowed_domains:
        raise Exception(f"Domain not in whitelist: {host}")

    # ── 3. Category filter ───────────────────────────────────────────────────
    if proxy.category_filter:
        category = await proxy.category_filter.categorize_with_external(host)
        if proxy.category_filter.is_blocked(category):
            raise Exception(f"Domain blocked by category '{category}': {host}")

    # ── 4. Rate limiting ─────────────────────────────────────────────────────
    if not proxy.security.check_rate_limit(client_ip):
        raise Exception(f"Rate limit exceeded for {client_ip}")

    # ── 5. Anomaly detection (alert only, never blocks) ──────────────────────
    if proxy.anomaly_detector and proxy.anomaly_detector.record(client_ip):
        from models import SecurityThreat, SecurityLevel as SL
        threat = SecurityThreat(
            level=SL.SUSPICIOUS,
            reason=(
                f"Traffic spike: >{proxy.anomaly_detector.threshold_rps} "
                f"reqs/{proxy.anomaly_detector.window_seconds}s"
            ),
            timestamp=datetime.utcnow().isoformat(),
            ip=client_ip,
            host=host,
        )
        asyncio.create_task(proxy.alerter.send(threat))
        proxy.sec_log.warning(f"ANOMALY spike from {client_ip} → {host}")
