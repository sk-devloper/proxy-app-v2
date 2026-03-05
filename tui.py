"""Textual TUI for J.A.R.V.I.S. Proxy"""
from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, List

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button, DataTable, Footer, Header, Label,
    RichLog, Sparkline, Static, TabbedContent, TabPane,
)

if TYPE_CHECKING:
    from proxy import JARVISProxy

from models import ConnectionMetrics, SecurityLevel

# ── helpers ───────────────────────────────────────────────────────────────────

def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def fmt_dur(s: float) -> str:
    if s < 60:    return f"{s:.0f}s"
    if s < 3600:  return f"{s/60:.1f}m"
    if s < 86400: return f"{s/3600:.1f}h"
    return f"{s/86400:.1f}d"

def fmt_ms(ms: float) -> str:
    if ms == 0:   return "[dim]--[/dim]"
    if ms < 1:    return f"{ms*1000:.0f}μs"
    if ms < 1000: return f"{ms:.1f}ms"
    return f"{ms/1000:.2f}s"

def status_color(code: int | None) -> str:
    if not code:   return "white"
    if code < 300: return "green"
    if code < 400: return "yellow"
    if code < 500: return "dark_orange"
    return "red"

def threat_color(level: SecurityLevel) -> str:
    return {
        SecurityLevel.SAFE:       "green",
        SecurityLevel.SUSPICIOUS: "yellow",
        SecurityLevel.MALICIOUS:  "red",
        SecurityLevel.BLOCKED:    "bright_red",
    }.get(level, "white")

def bar(pct: float, width: int = 16) -> str:
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)

# ── always-visible status bar ─────────────────────────────────────────────────

class StatusBar(Static):
    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: #161b22;
        color: #8b949e;
        padding: 0 2;
    }
    """
    def refresh_data(self, proxy: "JARVISProxy", rps: float) -> None:
        s = proxy.stats
        up = max(time.time() - s.start_time, 1)
        total_bw = s.total_bytes_sent + s.total_bytes_received
        cache_total = s.cache_hits + s.cache_misses
        hit_rate = s.cache_hits / cache_total * 100 if cache_total else 0
        avg_resp = sum(s.response_times) / len(s.response_times) if s.response_times else 0

        pause_badge = " [bold red]⏸ PAUSED[/bold red] │" if getattr(proxy, '_tui_paused', False) else ""
        ssl_badge = " [green]🔒SSL[/green]" if proxy.enable_ssl_inspection else ""
        wl_badge = " [cyan]📋WL[/cyan]" if s.whitelist_mode else ""

        self.update(
            f"[cyan]⚡ {rps:.1f} req/s[/cyan]"
            f" │ [yellow]🔗 {s.active_connections} active[/yellow]"
            f" │ [white]📊 {s.total_requests:,} total[/white]"
            f" │ [green]↑{fmt_bytes(s.current_upload_bps)}/s[/green]"
            f"  [blue]↓{fmt_bytes(s.current_download_bps)}/s[/blue]"
            f"  [dim](↑{fmt_bytes(s.total_bytes_sent)} ↓{fmt_bytes(s.total_bytes_received)} total)[/dim]"
            f" │ [magenta]💾 {hit_rate:.0f}% cache[/magenta]  [dim]{s.cache_hits}h/{s.cache_misses}m[/dim]"
            f" │ [white]⚡ {fmt_ms(avg_resp)}[/white]"
            f" │ [red]🛡 {s.threats_blocked} blocked[/red]"
            f" │ [dim]⏱ {fmt_dur(up)}[/dim]"
            f"{ssl_badge}{wl_badge}{pause_badge}"
        )

# ── sparkline block ───────────────────────────────────────────────────────────

class _SparkBlock(Vertical):
    """Label + Sparkline pair with fixed height."""
    DEFAULT_CSS = """
    _SparkBlock { height: 7; border: round #1f6feb; margin: 0 0 1 0; padding: 0 1; }
    _SparkBlock Label  { height: 1; color: #58a6ff; text-style: bold; }
    _SparkBlock Sparkline { height: 5; }
    """

# ── request inspector modal ───────────────────────────────────────────────────

class RequestInspectorScreen(ModalScreen):
    """Full-screen overlay showing all fields of a ConnectionMetrics."""
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q",      "dismiss", "Close"),
    ]
    DEFAULT_CSS = """
    RequestInspectorScreen {
        align: center middle;
    }
    #inspector-box {
        width: 80;
        height: auto;
        max-height: 90vh;
        background: #0d1117;
        border: double #1f6feb;
        padding: 1 2;
    }
    #inspector-title {
        text-style: bold;
        color: #58a6ff;
        height: 1;
        margin-bottom: 1;
    }
    #inspector-content { height: auto; }
    #inspector-footer  { height: 1; color: #484f58; margin-top: 1; }
    """

    def __init__(self, metrics: ConnectionMetrics):
        super().__init__()
        self._m = metrics

    def compose(self) -> ComposeResult:
        with Vertical(id="inspector-box"):
            yield Label("🔍 Request Inspector", id="inspector-title")
            yield Static(id="inspector-content")
            yield Label("[dim]ESC / Q — close[/dim]", id="inspector-footer")

    def on_mount(self) -> None:
        m = self._m
        ts = m.timestamp
        lock = "🔒 HTTPS" if m.is_https else "🔓 HTTP"
        sec_c = threat_color(m.security_level)

        geo = ""
        if m.geo_location:
            g = m.geo_location
            geo = (
                f"\n[cyan]Country   [/cyan] [white]{g.country}[/white]"
                f"  [dim]{g.city}[/dim]"
                f"\n[cyan]ISP       [/cyan] [white]{g.isp}[/white]"
                + (f"\n[yellow]⚠ VPN/Proxy detected[/yellow]" if g.is_vpn else "")
            )

        ssl_info = ""
        if m.ssl_info:
            s = m.ssl_info
            ssl_info = (
                f"\n[cyan]TLS Proto  [/cyan] [white]{s.protocol}[/white]"
                f"  [dim]{s.cipher}[/dim]"
            )

        req_hdrs = ""
        if m.request_headers:
            lines = [f"  [dim]{k}:[/dim] {v}" for k, v in list(m.request_headers.items())[:8]]
            req_hdrs = "\n[cyan]Request Headers[/cyan]\n" + "\n".join(lines)

        resp_hdrs = ""
        if m.response_headers:
            lines = [f"  [dim]{k}:[/dim] {v}" for k, v in list(m.response_headers.items())[:8]]
            resp_hdrs = "\n[cyan]Response Headers[/cyan]\n" + "\n".join(lines)

        err_line = f"\n[red]Error     [/red] {m.error}" if m.error else ""
        cached_badge = " [blue]💾 CACHED[/blue]" if m.cached else ""
        comp_badge   = " [dim](gzip)[/dim]" if m.compressed else ""

        content = (
            f"[cyan]Timestamp [/cyan] [white]{ts}[/white]\n"
            f"[cyan]Type      [/cyan] [white]{m.type}[/white]  {lock}\n"
            f"[cyan]Client    [/cyan] [white]{m.client_ip}[/white]\n"
            f"[cyan]Host      [/cyan] [bold white]{m.host}:{m.port}[/bold white]\n"
            f"[cyan]Method    [/cyan] [white]{m.method or '—'}[/white]\n"
            f"[cyan]URL       [/cyan] [dim]{(m.url or '—')[:68]}[/dim]\n"
            f"[cyan]Status    [/cyan] [{status_color(m.status_code)}]{m.status_code or '—'}[/{status_color(m.status_code)}]{cached_badge}{comp_badge}\n"
            f"[cyan]Body      [/cyan] [white]{fmt_bytes(m.body_bytes) if m.body_bytes else '—'}[/white]\n"
            f"[cyan]Resp Time [/cyan] [white]{fmt_ms(m.response_time_ms or 0)}[/white]\n"
            f"[cyan]TCP ms    [/cyan] [white]{fmt_ms(m.tcp_connect_ms)}[/white]\n"
            f"[cyan]DNS ms    [/cyan] [white]{fmt_ms(m.dns.dns_time_ms)}[/white]"
            f"  [dim]cached={m.dns.cached}  ipv6={m.dns.is_ipv6}[/dim]\n"
            f"[cyan]DNS IPs   [/cyan] [dim]{', '.join(m.dns.addresses[:3])}[/dim]\n"
            f"[cyan]Security  [/cyan] [{sec_c}]{m.security_level.value.upper()}[/{sec_c}]\n"
            f"[cyan]UA        [/cyan] [dim]{(m.user_agent or '—')[:68]}[/dim]"
            f"{geo}{ssl_info}{err_line}{req_hdrs}{resp_hdrs}"
        )
        self.query_one("#inspector-content", Static).update(content)

# ── dashboard pane ────────────────────────────────────────────────────────────

class DashboardPane(Vertical):
    DEFAULT_CSS = """
    DashboardPane            { layout: horizontal; height: 1fr; }
    DashboardPane #dash-left { width: 22; layout: vertical; }
    DashboardPane #dash-mid  { width: 1fr; layout: vertical; }
    DashboardPane #dash-right{ width: 30; layout: vertical; }

    DashboardPane #dash-stats  { border: round #1f6feb; padding: 0 1; margin: 0 0 1 0; height: auto; }
    DashboardPane #dash-cache  { border: round #1f6feb; padding: 0 1; margin: 0 0 1 0; height: auto; }
    DashboardPane #dash-alerts { border: round #1f6feb; padding: 0 1; height: 1fr; }
    DashboardPane DataTable    { border: round #1f6feb; height: 1fr; margin: 0 0 1 0; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dash-left"):
            yield Static(id="dash-stats")
            yield Static(id="dash-cache")
            yield Static(id="dash-alerts")
        with Vertical(id="dash-mid"):
            with _SparkBlock():
                yield Label("", id="lbl-resp")
                yield Sparkline([], id="spark-resp", min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-tcp")
                yield Sparkline([], id="spark-tcp", min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-rps")
                yield Sparkline([], id="spark-rps", min_color="#0088ff", max_color="#00ffff")
            with _SparkBlock():
                yield Label("", id="lbl-bw")
                yield Sparkline([], id="spark-bw-up", min_color="#00cc44", max_color="#00ff88")
                yield Sparkline([], id="spark-bw-dn", min_color="#ff8800", max_color="#ffcc00")
        with Vertical(id="dash-right"):
            yield DataTable(id="dash-status",  show_cursor=False)
            yield DataTable(id="dash-domains", show_cursor=False)

    def on_mount(self) -> None:
        sc = self.query_one("#dash-status", DataTable)
        sc.add_columns("Status", "Count", "Share")
        sc.border_title = "📡 Status Codes"

        dom = self.query_one("#dash-domains", DataTable)
        dom.add_columns("Domain", "Reqs", "ms")
        dom.border_title = "🏆 Top Domains"

    def refresh_data(self, proxy: "JARVISProxy", rps_history: deque) -> None:
        s = proxy.stats
        up = max(time.time() - s.start_time, 1)
        rps = s.total_requests / up
        ok_pct  = (s.total_requests - s.total_errors) / max(s.total_requests, 1) * 100
        https_p = s.https_requests / max(s.total_requests, 1) * 100
        total_bw = s.total_bytes_sent + s.total_bytes_received
        avg_dns  = sum(s.dns_times) / len(s.dns_times) if s.dns_times else 0
        avg_resp = sum(s.response_times) / len(s.response_times) if s.response_times else 0

        self.query_one("#dash-stats", Static).update(
            "[bold cyan]📊 OVERVIEW[/bold cyan]\n"
            f"[cyan]Requests [/cyan] [white]{s.total_requests:,}[/white]  [red]err {s.total_errors:,}[/red]\n"
            f"[cyan]Success  [/cyan] [green]{ok_pct:.1f}%[/green]  [dim]{rps:.1f} req/s[/dim]\n"
            f"[cyan]HTTPS    [/cyan] [green]{s.https_requests:,}[/green] [dim]({https_p:.0f}%)[/dim]\n"
            f"[cyan]HTTP     [/cyan] [blue]{s.http_requests:,}[/blue]\n"
            f"[cyan]Active   [/cyan] [yellow]{s.active_connections}[/yellow]  peak [yellow]{s.peak_connections}[/yellow]\n"
            f"[cyan]Clients  [/cyan] [white]{len(s.unique_clients):,}[/white]\n"
            f"[cyan]DNS avg  [/cyan] [white]{fmt_ms(avg_dns)}[/white]\n"
            f"[cyan]Resp avg [/cyan] [white]{fmt_ms(avg_resp)}[/white]\n"
            f"[cyan]↑ Sent   [/cyan] [green]{fmt_bytes(s.total_bytes_sent)}[/green]  [dim]{fmt_bytes(s.current_upload_bps)}/s[/dim]\n"
            f"[cyan]↓ Recv   [/cyan] [blue]{fmt_bytes(s.total_bytes_received)}[/blue]  [dim]{fmt_bytes(s.current_download_bps)}/s[/dim]\n"
            f"[cyan]Speed    [/cyan] [white]↑{fmt_bytes(s.current_upload_bps)}/s  ↓{fmt_bytes(s.current_download_bps)}/s[/white]"
        )

        cache_total = s.cache_hits + s.cache_misses
        hit_rate = s.cache_hits / cache_total * 100 if cache_total else 0
        hit_bar = bar(hit_rate, 16)
        self.query_one("#dash-cache", Static).update(
            "[bold cyan]💾 CACHE[/bold cyan]\n"
            f"[cyan]Hits    [/cyan] [green]{s.cache_hits:,}[/green]\n"
            f"[cyan]Misses  [/cyan] [red]{s.cache_misses:,}[/red]\n"
            f"[cyan]Rate    [/cyan] [blue]{hit_rate:.1f}%[/blue]\n"
            f"[cyan]        [/cyan] [blue]{hit_bar}[/blue]\n"
            f"[cyan]Entries [/cyan] [white]{len(proxy.cache.cache):,}[/white]\n"
            f"[cyan]Threats [/cyan] [red]{s.threats_blocked:,}[/red]  "
            f"[dim]{len(s.malicious_ips)} IPs[/dim]"
        )

        resp_data = list(s.response_times) or [0]
        tcp_data  = list(s.tcp_times) or [0]
        rps_data  = list(rps_history) or [0]
        up_data   = list(s.upload_bps_history)   or [0]
        dn_data   = list(s.download_bps_history) or [0]
        self.query_one("#spark-resp",  Sparkline).data = resp_data
        self.query_one("#spark-tcp",   Sparkline).data = tcp_data
        self.query_one("#spark-rps",   Sparkline).data = rps_data
        self.query_one("#spark-bw-up", Sparkline).data = up_data
        self.query_one("#spark-bw-dn", Sparkline).data = dn_data

        avg_resp = sum(resp_data) / len(resp_data)
        avg_tcp  = sum(tcp_data)  / len(tcp_data)
        avg_rps  = sum(rps_data)  / len(rps_data)
        self.query_one("#lbl-resp", Label).update(
            f"⚡ Response Time  [dim]avg [yellow]{fmt_ms(avg_resp)}[/yellow]  max [red]{fmt_ms(max(resp_data))}[/red][/dim]")
        self.query_one("#lbl-tcp",  Label).update(
            f"🔌 TCP Connect    [dim]avg [yellow]{fmt_ms(avg_tcp)}[/yellow]  max [red]{fmt_ms(max(tcp_data))}[/red][/dim]")
        self.query_one("#lbl-rps",  Label).update(
            f"📡 Requests/sec   [dim]avg [cyan]{avg_rps:.1f}[/cyan]  peak [cyan]{max(rps_data):.1f}[/cyan][/dim]")
        self.query_one("#lbl-bw",   Label).update(
            f"📶 Bandwidth      [dim][green]↑{fmt_bytes(s.current_upload_bps)}/s[/green]"
            f"  [yellow]↓{fmt_bytes(s.current_download_bps)}/s[/yellow][/dim]")

        alerts = list(proxy.alerts)[-6:]
        alerts.reverse()
        lines = ["[bold cyan]🔔 RECENT ALERTS[/bold cyan]"]
        colors = {"SYSTEM": "cyan", "SECURITY": "red", "TUI": "magenta"}
        for a in alerts:
            c = colors.get(a["type"], "white")
            lines.append(f"[dim]{a['time']}[/dim] [{c}]{a['type']:8}[/{c}] {a['message']}")
        self.query_one("#dash-alerts", Static).update("\n".join(lines))

        sc = self.query_one("#dash-status", DataTable)
        sc.clear()
        total_sc = sum(s.status_codes.values())
        for code, count in sorted(s.status_codes.items(), key=lambda x: x[1], reverse=True)[:8]:
            pct = count / total_sc * 100 if total_sc else 0
            c   = status_color(code)
            sc.add_row(f"[{c}]{code}[/{c}]", f"{count:,}", f"[{c}]{bar(pct, 10)}[/{c}] {pct:.0f}%")

        dom = self.query_one("#dash-domains", DataTable)
        dom.clear()
        for domain, ds in sorted(
            s.domain_stats.items(), key=lambda x: x[1]["requests"], reverse=True
        )[:10]:
            dom.add_row(domain[:30], f"{ds['requests']:,}", fmt_ms(ds["avg_time"]))

# ── traffic pane ──────────────────────────────────────────────────────────────

class TrafficPane(Vertical):
    DEFAULT_CSS = """
    TrafficPane { padding: 0; }
    TrafficPane DataTable { height: 1fr; border: round #1f6feb; }
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._recent: List[ConnectionMetrics] = []

    def compose(self) -> ComposeResult:
        yield DataTable(id="traffic-table", show_cursor=True, cursor_type="row")

    def on_mount(self) -> None:
        t = self.query_one("#traffic-table", DataTable)
        t.add_columns("Time", "🔒", "⚡", "Method", "Client", "Host", "Status", "Size", "Time", "User-Agent")
        t.border_title = "📡 Live Traffic  (newest first, 50 rows) — Enter to inspect"

    def refresh_data(self, proxy: "JARVISProxy") -> None:
        t = self.query_one("#traffic-table", DataTable)
        t.clear()
        recent = list(proxy.stats.recent_requests)[-50:]
        recent.reverse()
        self._recent = recent
        for req in recent:
            ts     = datetime.fromisoformat(req.timestamp).strftime("%H:%M:%S")
            lock   = "🔒" if req.is_https else "  "
            method = (req.method or "CONN")[:6]
            client = req.client_ip or "-"
            host   = req.host[:32] if req.host else "-"
            ua     = (req.user_agent or "-")[:30]

            lc = threat_color(req.security_level)
            if req.security_level == SecurityLevel.SAFE:
                sec = f"[{lc}]●[/{lc}]"
            elif req.security_level == SecurityLevel.SUSPICIOUS:
                sec = f"[{lc}]▲[/{lc}]"
            else:
                sec = f"[{lc}]✖[/{lc}]"

            if req.status_code:
                c      = status_color(req.status_code)
                status = f"[{c}]{req.status_code}[/{c}]"
            else:
                status = "[dim]—[/dim]"
            if req.error:
                host   = f"[red]{host}[/red]"
                status = "[red]ERR[/red]"

            size = fmt_bytes(req.body_bytes) if req.body_bytes else "—"
            if req.cached:
                size = f"[blue]💾{size}[/blue]"

            rt = fmt_ms(req.response_time_ms) if req.response_time_ms else "[dim]—[/dim]"
            t.add_row(ts, lock, sec, method, client, host, status, size, rt, ua)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._recent):
            self.app.push_screen(RequestInspectorScreen(self._recent[idx]))

# ── security pane ─────────────────────────────────────────────────────────────

class SecurityPane(Horizontal):
    DEFAULT_CSS = """
    SecurityPane #threats-table { width: 3fr; height: 1fr; border: round #ff4444; }
    SecurityPane #sec-side { width: 1fr; layout: vertical; }
    SecurityPane #sec-side Static { border: round #1f6feb; padding: 0 1; margin: 0 0 1 0; height: auto; }
    """
    def compose(self) -> ComposeResult:
        yield DataTable(id="threats-table", show_cursor=False)
        with Vertical(id="sec-side"):
            yield Static(id="sec-summary")
            yield Static(id="blocklist-panel")

    def on_mount(self) -> None:
        t = self.query_one("#threats-table", DataTable)
        t.add_columns("Time", "Level", "IP", "Host", "Reason", "Patterns")
        t.border_title = "🛡️  Security Threats"

    def refresh_data(self, proxy: "JARVISProxy") -> None:
        s = proxy.stats
        t = self.query_one("#threats-table", DataTable)
        t.clear()
        threats = list(s.security_threats)[-40:]
        threats.reverse()
        _labels = {
            SecurityLevel.SAFE:       ("SAFE",    "green"),
            SecurityLevel.SUSPICIOUS: ("SUSPECT",  "yellow"),
            SecurityLevel.MALICIOUS:  ("MALICIOUS","red"),
            SecurityLevel.BLOCKED:    ("BLOCKED",  "bright_red"),
        }
        for th in threats:
            lbl, lc = _labels.get(th.level, (th.level.value.upper(), "white"))
            ts = th.timestamp[11:19] if len(th.timestamp) > 10 else th.timestamp
            t.add_row(
                ts,
                f"[{lc}]{lbl}[/{lc}]",
                th.ip, th.host[:26], th.reason[:34],
                ", ".join(th.patterns[:1])[:24],
            )
        if not threats:
            t.add_row("—", "[green]NONE[/green]", "—", "No threats detected", "—", "—")

        wl = "[bold green]ON[/bold green]" if s.whitelist_mode else "[dim]off[/dim]"
        self.query_one("#sec-summary", Static).update(
            "[bold cyan]🛡️  SUMMARY[/bold cyan]\n"
            f"[cyan]Blocked    [/cyan] [red]{s.threats_blocked:,}[/red]\n"
            f"[cyan]Mal. IPs   [/cyan] [red]{len(s.malicious_ips)}[/red]\n"
            f"[cyan]Threats    [/cyan] [white]{len(s.security_threats)}[/white]\n"
            f"[cyan]Whitelist  [/cyan] {wl}\n"
            f"[cyan]Blocked    [/cyan] [white]{len(s.blocked_domains)} domains[/white]\n"
            f"[cyan]Allowed    [/cyan] [white]{len(s.allowed_domains)} domains[/white]"
        )

        blocked = "\n".join(f"  [red]✗[/red] {d}" for d in sorted(s.blocked_domains)) or "  [dim](none)[/dim]"
        allowed = "\n".join(f"  [green]✓[/green] {d}" for d in sorted(s.allowed_domains)) or "  [dim](none)[/dim]"
        self.query_one("#blocklist-panel", Static).update(
            f"[bold cyan]🚫 Blocklist[/bold cyan]\n{blocked}\n\n"
            f"[bold cyan]✅ Allowlist[/bold cyan]  {wl}\n{allowed}"
        )

# ── domains pane ──────────────────────────────────────────────────────────────

class DomainsPane(Horizontal):
    DEFAULT_CSS = """
    DomainsPane #domains-table { width: 3fr; height: 1fr; border: round #1f6feb; }
    DomainsPane #dom-side { width: 1fr; layout: vertical; }
    DomainsPane #dom-side DataTable { border: round #1f6feb; height: 1fr; }
    """
    def compose(self) -> ComposeResult:
        yield DataTable(id="domains-table", show_cursor=False)
        with Vertical(id="dom-side"):
            yield DataTable(id="methods-table", show_cursor=False)

    def on_mount(self) -> None:
        t = self.query_one("#domains-table", DataTable)
        t.add_columns("Domain", "Reqs", "Errors", "Err%", "Avg ms", "Data", "Top Methods")
        t.border_title = "🌐 Domain Analytics"

        m = self.query_one("#methods-table", DataTable)
        m.add_columns("Method/Code", "Count")
        m.border_title = "📊 Methods & Codes"

    def refresh_data(self, proxy: "JARVISProxy") -> None:
        s = proxy.stats
        t = self.query_one("#domains-table", DataTable)
        t.clear()
        for domain, ds in sorted(
            s.domain_stats.items(), key=lambda x: x[1]["requests"], reverse=True
        )[:45]:
            err_pct = ds["errors"] / ds["requests"] * 100 if ds["requests"] else 0
            methods = " ".join(f"{m}:{c}" for m, c in ds["methods"].most_common(2))
            t.add_row(
                domain[:38], f"{ds['requests']:,}", f"{ds['errors']:,}",
                f"{err_pct:.0f}%", fmt_ms(ds["avg_time"]), fmt_bytes(ds["bytes"]), methods[:18],
            )

        m = self.query_one("#methods-table", DataTable)
        m.clear()
        m.add_row("[bold cyan]── Methods ──[/bold cyan]", "")
        for method, count in s.methods.most_common():
            m.add_row(f"[cyan]{method}[/cyan]", f"{count:,}")
        m.add_row("[bold cyan]── Codes ────[/bold cyan]", "")
        for code, count in sorted(s.status_codes.items(), key=lambda x: x[1], reverse=True)[:12]:
            c = status_color(code)
            m.add_row(f"[{c}]{code}[/{c}]", f"{count:,}")

# ── performance pane ──────────────────────────────────────────────────────────

class PerformancePane(Horizontal):
    DEFAULT_CSS = """
    PerformancePane { height: 1fr; }
    PerformancePane #perf-sparks   { width: 1fr; layout: vertical; }
    PerformancePane #perf-summary  { width: 26; border: round #1f6feb; padding: 0 1; margin: 0 0 0 1; }
    PerformancePane _SparkBlock    { height: 1fr; }
    """
    def compose(self) -> ComposeResult:
        with Vertical(id="perf-sparks"):
            with _SparkBlock():
                yield Label("", id="lbl-dns")
                yield Sparkline([], id="sp-dns",  min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-tcp2")
                yield Sparkline([], id="sp-tcp",  min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-ssl")
                yield Sparkline([], id="sp-ssl",  min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-resp2")
                yield Sparkline([], id="sp-resp", min_color="#00cc44", max_color="#ff3333")
            with _SparkBlock():
                yield Label("", id="lbl-rps2")
                yield Sparkline([], id="sp-rps2", min_color="#0088ff", max_color="#00ffff")
        yield Static(id="perf-summary")

    def refresh_data(self, proxy: "JARVISProxy", rps_history: deque) -> None:
        s = proxy.stats

        def _upd(sp_id: str, lbl_id: str, label: str, vals: list) -> None:
            data = vals or [0]
            self.query_one(sp_id,  Sparkline).data = data
            avg = sum(data) / len(data)
            mx  = max(data)
            self.query_one(lbl_id, Label).update(
                f"{label}  [dim]avg [yellow]{fmt_ms(avg)}[/yellow]  "
                f"max [red]{fmt_ms(mx)}[/red]  n={len(data)}[/dim]"
            )

        _upd("#sp-dns",  "#lbl-dns",   "🔍 DNS Latency",     list(s.dns_times))
        _upd("#sp-tcp",  "#lbl-tcp2",  "🔌 TCP Connect",     list(s.tcp_times))
        _upd("#sp-ssl",  "#lbl-ssl",   "🔒 SSL Handshake",   list(s.ssl_times) or [0])
        _upd("#sp-resp", "#lbl-resp2", "⚡ Response/Tunnel",  list(s.response_times))

        rps_data = list(rps_history) or [0]
        self.query_one("#sp-rps2", Sparkline).data = rps_data
        avg_rps = sum(rps_data) / len(rps_data)
        self.query_one("#lbl-rps2", Label).update(
            f"📡 Requests/sec  [dim]avg [cyan]{avg_rps:.1f}[/cyan]  "
            f"peak [cyan]{max(rps_data):.1f}[/cyan][/dim]"
        )

        up = max(time.time() - s.start_time, 1)
        total_bw = s.total_bytes_sent + s.total_bytes_received
        self.query_one("#perf-summary", Static).update(
            "[bold cyan]📊 SUMMARY[/bold cyan]\n"
            f"[cyan]Uptime     [/cyan] [white]{fmt_dur(up)}[/white]\n"
            f"[cyan]Total Reqs [/cyan] [white]{s.total_requests:,}[/white]\n"
            f"[cyan]BW/s       [/cyan] [white]{fmt_bytes(total_bw/up)}/s[/white]\n"
            f"[cyan]Total BW   [/cyan] [white]{fmt_bytes(total_bw)}[/white]\n"
            f"[cyan]Peak Conn  [/cyan] [yellow]{s.peak_connections}[/yellow]\n"
            f"[cyan]Clients    [/cyan] [white]{len(s.unique_clients):,}[/white]\n"
            f"[cyan]Cache Rate [/cyan] [blue]"
            + (f"{s.cache_hits/(s.cache_hits+s.cache_misses)*100:.1f}%" if (s.cache_hits+s.cache_misses) else "—")
            + "[/blue]"
        )

# ── geo pane ──────────────────────────────────────────────────────────────────

class GeoPane(Horizontal):
    DEFAULT_CSS = """
    GeoPane #geo-table  { width: 2fr; height: 1fr; border: round #1f6feb; }
    GeoPane #geo-right  { width: 1fr; layout: vertical; }
    GeoPane #geo-right DataTable { border: round #1f6feb; height: 1fr; }
    """
    def compose(self) -> ComposeResult:
        yield DataTable(id="geo-table",  show_cursor=False)
        with Vertical(id="geo-right"):
            yield DataTable(id="ct-table",  show_cursor=False)
            yield DataTable(id="cli-table", show_cursor=False)

    def on_mount(self) -> None:
        g = self.query_one("#geo-table", DataTable)
        g.add_columns("🌍 Country", "Requests", "Share")
        g.border_title = "🌍 Geographic Breakdown"

        ct = self.query_one("#ct-table", DataTable)
        ct.add_columns("📄 Type", "Count", "%")
        ct.border_title = "📄 Content Types"

        cl = self.query_one("#cli-table", DataTable)
        cl.add_columns("👤 Client IP", "Requests")
        cl.border_title = "👥 Top Clients"

    def refresh_data(self, proxy: "JARVISProxy") -> None:
        s = proxy.stats

        g = self.query_one("#geo-table", DataTable)
        g.clear()
        total_geo = sum(s.geo_stats.values())
        for country, count in sorted(s.geo_stats.items(), key=lambda x: x[1], reverse=True):
            pct = count / total_geo * 100 if total_geo else 0
            g.add_row(country, f"{count:,}", f"[cyan]{bar(pct, 18)}[/cyan] {pct:.1f}%")
        if not s.geo_stats:
            g.add_row("[dim]No data yet[/dim]", "—", "—")

        ct = self.query_one("#ct-table", DataTable)
        ct.clear()
        total_ct = sum(s.content_types.values())
        for ctype, count in s.content_types.most_common():
            pct = count / total_ct * 100 if total_ct else 0
            ct.add_row(ctype.value.upper(), f"{count:,}", f"{pct:.0f}%")
        if not s.content_types:
            ct.add_row("[dim]No data[/dim]", "—", "—")

        cl = self.query_one("#cli-table", DataTable)
        cl.clear()
        for ip, count in sorted(s.client_requests.items(), key=lambda x: x[1], reverse=True)[:20]:
            cl.add_row(ip, f"{count:,}")
        if not s.client_requests:
            cl.add_row("[dim]No data[/dim]", "—")

# ── live log pane ─────────────────────────────────────────────────────────────

class LogPane(Vertical):
    """Scrolling live log stream of all proxied requests."""
    DEFAULT_CSS = """
    LogPane { padding: 0; }
    LogPane #log-controls { height: 3; border: round #1f6feb; padding: 0 1; }
    LogPane RichLog { height: 1fr; border: round #1f6feb; }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._written = 0   # tracks proxy.stats.log_total items already written

    def compose(self) -> ComposeResult:
        yield Static(id="log-controls")
        yield RichLog(id="log-richlog", highlight=True, markup=True, wrap=False)

    def on_mount(self) -> None:
        log = self.query_one("#log-richlog", RichLog)
        log.border_title = "📜 Live Request Log  (auto-scroll)"
        self.query_one("#log-controls", Static).update(
            "[bold cyan]📜 LIVE LOG[/bold cyan]  "
            "[dim]All traffic is streamed here in real time. "
            "Colors: [green]●safe[/green]  [yellow]▲suspicious[/yellow]  [red]✖malicious[/red]  "
            "[bright_red]■blocked[/bright_red][/dim]"
        )

    def refresh_data(self, proxy: "JARVISProxy") -> None:
        new_total = proxy.stats.log_total
        if new_total <= self._written:
            return
        new_count = new_total - self._written
        lines = proxy.stats.log_lines
        to_write = lines[-min(new_count, len(lines)):]
        log = self.query_one("#log-richlog", RichLog)
        colors = {
            "safe":       "green",
            "suspicious": "yellow",
            "malicious":  "red",
            "blocked":    "bright_red",
        }
        for ts, sec, msg in to_write:
            c = colors.get(sec, "white")
            log.write(f"[dim]{ts}[/dim] [{c}]●[/{c}] {msg}")
        self._written = new_total

# ── history pane ──────────────────────────────────────────────────────────────

class HistoryPane(Vertical):
    """Long-term req/min and req/hr sparklines."""
    DEFAULT_CSS = """
    HistoryPane { height: 1fr; layout: vertical; }
    HistoryPane #hist-summary { height: auto; border: round #1f6feb; padding: 0 1; margin: 0 0 1 0; }
    HistoryPane _SparkBlock   { height: 1fr; }
    """

    def compose(self) -> ComposeResult:
        yield Static(id="hist-summary")
        with _SparkBlock():
            yield Label("", id="lbl-min-rps")
            yield Sparkline([], id="sp-min-rps", min_color="#0088ff", max_color="#00ffff")
        with _SparkBlock():
            yield Label("", id="lbl-hr-rps")
            yield Sparkline([], id="sp-hr-rps",  min_color="#00cc44", max_color="#ff8800")

    def refresh_data(self, proxy: "JARVISProxy", minute_history: deque, hour_history: deque) -> None:
        s = proxy.stats
        up = max(time.time() - s.start_time, 1)

        # minute sparkline
        min_data = list(minute_history) or [0]
        self.query_one("#sp-min-rps", Sparkline).data = min_data
        avg_min = sum(min_data) / len(min_data)
        peak_min = max(min_data)
        self.query_one("#lbl-min-rps", Label).update(
            f"📡 Req/min — last {len(min_data)} minutes  "
            f"[dim]avg [cyan]{avg_min:.0f}[/cyan]  peak [cyan]{peak_min:.0f}[/cyan][/dim]"
        )

        # hour sparkline
        hr_data = list(hour_history) or [0]
        self.query_one("#sp-hr-rps", Sparkline).data = hr_data
        avg_hr = sum(hr_data) / len(hr_data)
        peak_hr = max(hr_data)
        self.query_one("#lbl-hr-rps", Label).update(
            f"🕐 Req/hr  — last {len(hr_data)} hours  "
            f"[dim]avg [green]{avg_hr:.0f}[/green]  peak [green]{peak_hr:.0f}[/green][/dim]"
        )

        total_bw = s.total_bytes_sent + s.total_bytes_received
        self.query_one("#hist-summary", Static).update(
            "[bold cyan]📈 HISTORICAL OVERVIEW[/bold cyan]  "
            f"[dim]uptime {fmt_dur(up)}[/dim]\n"
            f"[cyan]Total Requests [/cyan] [white]{s.total_requests:,}[/white]"
            f"   [cyan]Errors [/cyan] [red]{s.total_errors:,}[/red]"
            f"   [cyan]Bandwidth [/cyan] [white]{fmt_bytes(total_bw)}[/white]"
            f"   [cyan]Clients [/cyan] [white]{len(s.unique_clients):,}[/white]"
            f"   [cyan]Domains [/cyan] [white]{len(s.domain_stats):,}[/white]"
        )

# ── main app ──────────────────────────────────────────────────────────────────

class JARVISApp(App):
    """J.A.R.V.I.S. Proxy TUI"""

    CSS = """
    Screen { background: #0d1117; }

    Header { background: #1f6feb; color: white; text-style: bold; }
    Footer { background: #0d1117; color: #484f58; }

    TabbedContent { height: 1fr; }
    TabPane       { padding: 0; height: 1fr; }

    Tabs { background: #161b22; }
    Tab  { color: #8b949e; }
    Tab:focus { color: #f0f6fc; }
    Tab.-active { color: #58a6ff; text-style: bold; }

    DataTable { height: 1fr; }
    DataTable > .datatable--header     { background: #161b22; color: #58a6ff; text-style: bold; }
    DataTable > .datatable--odd-row    { background: #0d1117; }
    DataTable > .datatable--even-row   { background: #161b22; }
    DataTable > .datatable--cursor     { background: #1f6feb33; }

    Sparkline { height: 5; }
    Label.spark-label { height: 1; color: #58a6ff; text-style: bold; margin: 0 0 0 1; }
    Static { color: #c9d1d9; }
    """

    BINDINGS = [
        Binding("1", "switch_tab('dashboard')",   "1 Dashboard",  show=True),
        Binding("2", "switch_tab('traffic')",     "2 Traffic",    show=True),
        Binding("3", "switch_tab('security')",    "3 Security",   show=True),
        Binding("4", "switch_tab('domains')",     "4 Domains",    show=True),
        Binding("5", "switch_tab('performance')", "5 Perf",       show=True),
        Binding("6", "switch_tab('geo')",         "6 Geo",        show=True),
        Binding("7", "switch_tab('log')",         "7 Log",        show=True),
        Binding("8", "switch_tab('history')",     "8 History",    show=True),
        Binding("p", "pause",        "Pause",      show=True),
        Binding("c", "clear_cache",  "Clear Cache",show=True),
        Binding("s", "save_stats",   "Save",       show=True),
        Binding("w", "whitelist",    "Whitelist",  show=True),
        Binding("q", "quit_proxy",   "Quit",       show=True),
    ]

    def __init__(self, proxy: "JARVISProxy"):
        super().__init__()
        self.proxy = proxy
        self._rps_history:    deque[float] = deque(maxlen=60)
        self._minute_history: deque[float] = deque(maxlen=60)
        self._hour_history:   deque[float] = deque(maxlen=24)
        self._last_count        = proxy.stats.total_requests
        self._last_minute_count = proxy.stats.total_requests
        self._last_hour_count   = proxy.stats.total_requests
        self._last_tick         = time.time()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar(id="status-bar")
        with TabbedContent(id="main-tabs", initial="dashboard"):
            with TabPane("📊 Dashboard",   id="dashboard"):
                yield DashboardPane(id="dashboard-pane")
            with TabPane("📡 Traffic",     id="traffic"):
                yield TrafficPane(id="traffic-pane")
            with TabPane("🛡️  Security",   id="security"):
                yield SecurityPane(id="security-pane")
            with TabPane("🌐 Domains",     id="domains"):
                yield DomainsPane(id="domains-pane")
            with TabPane("⚡ Performance", id="performance"):
                yield PerformancePane(id="performance-pane")
            with TabPane("🌍 Geo",         id="geo"):
                yield GeoPane(id="geo-pane")
            with TabPane("📜 Log",         id="log"):
                yield LogPane(id="log-pane")
            with TabPane("📈 History",     id="history"):
                yield HistoryPane(id="history-pane")
        yield Footer()

    def on_mount(self) -> None:
        self.title     = "⚡ J.A.R.V.I.S. HTTPS PROXY"
        self.sub_title = f"{self.proxy.host}:{self.proxy.port}"
        self.set_interval(0.5,    self._tick_rps)
        self.set_interval(60.0,   self._tick_minute)
        self.set_interval(3600.0, self._tick_hour)
        self.set_interval(0.25,   self._refresh_active_pane)
        self.set_interval(0.25,   self._refresh_statusbar)
        # restore persisted history if available
        if self.proxy.stats.minute_rps:
            self._minute_history.extend(self.proxy.stats.minute_rps)
        if self.proxy.stats.hour_rps:
            self._hour_history.extend(self.proxy.stats.hour_rps)

    # ── periodic ──────────────────────────────────────────────────────────────

    def _tick_rps(self) -> None:
        now   = time.time()
        delta = now - self._last_tick
        if delta > 0:
            new_count = self.proxy.stats.total_requests
            rps = (new_count - self._last_count) / delta
            self._rps_history.append(rps)
            self._last_count = new_count
            self._last_tick  = now

    def _tick_minute(self) -> None:
        new_count = self.proxy.stats.total_requests
        rpm = new_count - self._last_minute_count
        self._minute_history.append(float(rpm))
        self._last_minute_count = new_count
        # persist in stats for save_stats pickling
        self.proxy.stats.minute_rps = deque(self._minute_history, maxlen=60)

    def _tick_hour(self) -> None:
        new_count = self.proxy.stats.total_requests
        rph = new_count - self._last_hour_count
        self._hour_history.append(float(rph))
        self._last_hour_count = new_count
        self.proxy.stats.hour_rps = deque(self._hour_history, maxlen=24)

    def _refresh_statusbar(self) -> None:
        rps = self._rps_history[-1] if self._rps_history else 0
        try:
            self.query_one("#status-bar", StatusBar).refresh_data(self.proxy, rps)
        except Exception:
            pass

    def _refresh_active_pane(self) -> None:
        if getattr(self.proxy, '_tui_paused', False):
            return
        tc     = self.query_one("#main-tabs", TabbedContent)
        active = tc.active
        try:
            if active == "dashboard":
                self.query_one("#dashboard-pane", DashboardPane).refresh_data(self.proxy, self._rps_history)
            elif active == "traffic":
                self.query_one("#traffic-pane", TrafficPane).refresh_data(self.proxy)
            elif active == "security":
                self.query_one("#security-pane", SecurityPane).refresh_data(self.proxy)
            elif active == "domains":
                self.query_one("#domains-pane", DomainsPane).refresh_data(self.proxy)
            elif active == "performance":
                self.query_one("#performance-pane", PerformancePane).refresh_data(self.proxy, self._rps_history)
            elif active == "geo":
                self.query_one("#geo-pane", GeoPane).refresh_data(self.proxy)
            elif active == "log":
                self.query_one("#log-pane", LogPane).refresh_data(self.proxy)
            elif active == "history":
                self.query_one("#history-pane", HistoryPane).refresh_data(
                    self.proxy, self._minute_history, self._hour_history)
        except Exception:
            pass

    # ── actions ───────────────────────────────────────────────────────────────

    def action_switch_tab(self, tab: str) -> None:
        self.query_one("#main-tabs", TabbedContent).active = tab

    def action_pause(self) -> None:
        paused = not getattr(self.proxy, '_tui_paused', False)
        self.proxy._tui_paused = paused
        state = "PAUSED ⏸" if paused else "LIVE ▶"
        self.sub_title = f"{self.proxy.host}:{self.proxy.port}  {state}"
        self.proxy.add_alert("TUI", f"Display {state}")
        self.notify("Display paused" if paused else "Display resumed",
                    severity="warning" if paused else "information")

    def action_clear_cache(self) -> None:
        self.proxy.cache.cache.clear()
        self.proxy.stats.cache_hits   = 0
        self.proxy.stats.cache_misses = 0
        self.proxy.add_alert("TUI", "Cache cleared")
        self.notify("Cache cleared ✓", severity="information")

    def action_save_stats(self) -> None:
        self.proxy.save_stats()
        self.proxy.add_alert("TUI", "Stats saved")
        self.notify("Stats saved to disk ✓", severity="information")

    def action_whitelist(self) -> None:
        if self.proxy.stats.whitelist_mode:
            self.proxy.disable_whitelist_mode()
            self.notify("Whitelist mode OFF", severity="warning")
        else:
            self.proxy.enable_whitelist_mode()
            self.notify("Whitelist mode ON", severity="information")

    def action_quit_proxy(self) -> None:
        self.proxy.running = False
        if self.proxy.server:
            self.proxy.server.close()
        self.exit()
