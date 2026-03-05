"""Ad-block list auto-sync for J.A.R.V.I.S. Proxy.

Downloads popular blocklists and merges them into filters/blocklist.txt.
Runs as a background asyncio task.  Zero new runtime dependencies
(uses aiohttp which is already required).

Supported formats:
  - hosts  (127.0.0.1 <domain> / 0.0.0.0 <domain>)
  - domains (one domain per line)
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import List, Set

import aiohttp

log = logging.getLogger("JARVIS.blocklist_sync")

_DEFAULT_LISTS = [
    {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "name": "StevenBlack unified hosts",
    },
    {
        "url": "https://someonewhocares.org/hosts/hosts",
        "format": "hosts",
        "name": "Dan Pollock hosts",
    },
]


def _parse_hosts(text: str) -> Set[str]:
    domains: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].lower()
            if domain and "." in domain and domain not in ("localhost", "0.0.0.0"):
                domains.add(domain)
    return domains


def _parse_domains(text: str) -> Set[str]:
    domains: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#")[0].strip().lower()
        if line and "." in line:
            domains.add(line)
    return domains


async def _fetch(session: aiohttp.ClientSession, url: str) -> str:
    timeout = aiohttp.ClientTimeout(total=30)
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        return await resp.text(errors="ignore")


async def sync_once(
    lists: List[dict] | None = None,
    output_file: str = "filters/blocklist.txt",
) -> int:
    """Download and merge blocklists. Returns number of new domains added."""
    sources = lists or _DEFAULT_LISTS
    new_domains: Set[str] = set()

    async with aiohttp.ClientSession() as session:
        for src in sources:
            try:
                text = await _fetch(session, src["url"])
                fmt = src.get("format", "domains")
                if fmt == "hosts":
                    new_domains |= _parse_hosts(text)
                else:
                    new_domains |= _parse_domains(text)
                log.info(f"Fetched {src['name']}: {len(new_domains)} domains so far")
            except Exception as exc:
                log.warning(f"Failed to fetch {src.get('name', src['url'])}: {exc}")

    if not new_domains:
        return 0

    out = Path(output_file)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Load existing custom entries (preserve user comments and manual entries)
    existing: Set[str] = set()
    custom_lines: List[str] = []
    if out.exists():
        for raw in out.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                custom_lines.append(raw)
                continue
            domain = line.split("#")[0].strip().lower()
            existing.add(domain)

    added = new_domains - existing
    if not added:
        log.info("Blocklist already up to date")
        return 0

    with out.open("a") as f:
        f.write(f"\n# ── Auto-synced {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ────────────────\n")
        for domain in sorted(added):
            f.write(f"{domain}\n")

    log.info(f"Added {len(added)} new domains to {output_file}")
    return len(added)


async def sync_loop(
    interval_hours: float = 24,
    lists: List[dict] | None = None,
    output_file: str = "filters/blocklist.txt",
) -> None:
    """Background task: sync blocklists every *interval_hours* hours."""
    while True:
        try:
            added = await sync_once(lists=lists, output_file=output_file)
            log.info(f"Blocklist sync complete: {added} new domains. Next sync in {interval_hours}h")
        except Exception as exc:
            log.error(f"Blocklist sync error: {exc}")
        await asyncio.sleep(interval_hours * 3600)
