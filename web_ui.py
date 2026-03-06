"""J.A.R.V.I.S. Web UI — asyncio HTTP + SSE server, zero extra dependencies.

Accessible from any device on the LAN at http://<host>:<web_ui_port>
Streams live stats via Server-Sent Events every 250 ms.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections import deque
from typing import TYPE_CHECKING, Set

if TYPE_CHECKING:
    from proxy import JARVISProxy

log = logging.getLogger("JARVIS.webui")

# ── embedded single-file dashboard ───────────────────────────────────────────

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>\u26a1 J.A.R.V.I.S. Proxy</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --border:#1f6feb;--accent:#58a6ff;
  --text:#c9d1d9;--dim:#8b949e;
  --green:#3fb950;--red:#f85149;--yellow:#d29922;
  --orange:#db6d28;--blue:#79c0ff;--cyan:#56d364;--magenta:#bc8cff;
  --font:'Cascadia Code','Consolas','SF Mono','Fira Code',monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;overflow:hidden}
#app{display:flex;flex-direction:column;height:100vh}
/* header */
#header{background:#1f6feb;color:#fff;font-weight:bold;padding:4px 12px;display:flex;align-items:center;gap:10px;flex-shrink:0;min-height:28px}
#header-title{font-size:14px;letter-spacing:1px}
#conn-status{margin-left:auto;font-size:11px;transition:color .3s}
/* status bar */
#statusbar{background:var(--bg2);color:var(--dim);padding:3px 12px;font-size:11px;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
/* tabs */
#tabs{background:var(--bg2);border-bottom:1px solid var(--border);display:flex;flex-shrink:0;overflow-x:auto}
.tab-btn{background:none;border:none;color:var(--dim);padding:6px 13px;cursor:pointer;font-family:var(--font);font-size:12px;border-bottom:2px solid transparent;white-space:nowrap}
.tab-btn:hover{color:var(--text)}.tab-btn.active{color:var(--accent);font-weight:bold;border-bottom-color:var(--accent)}
/* panes */
#main{flex:1;overflow:hidden;position:relative}
.tab-pane{position:absolute;inset:0;display:none;overflow:hidden}
.tab-pane.active{display:flex;flex-direction:column}
.content{flex:1;overflow:hidden}
/* panels */
.panel{border:1px solid var(--border);border-radius:4px;padding:6px 8px;overflow:hidden}
.panel-title{color:var(--accent);font-weight:bold;margin-bottom:4px;font-size:12px}
/* tables */
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{background:var(--bg2);color:var(--accent);font-weight:bold;padding:3px 6px;text-align:left;position:sticky;top:0;z-index:1}
.tbl td{padding:2px 6px;border-bottom:1px solid #1a1f26}
.tbl tr:nth-child(even) td{background:var(--bg2)}
.tbl tr.clickable:hover td{background:#1f6feb22;cursor:pointer}
.tbl-wrap{overflow:auto;flex:1}
/* sparklines */
.spark-block{border:1px solid var(--border);border-radius:4px;padding:4px 6px;margin-bottom:6px;display:flex;flex-direction:column;min-height:70px}
.spark-label{color:var(--accent);font-size:11px;font-weight:bold;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
canvas.spark{flex:1;width:100%;min-height:40px;display:block}
/* kv list */
.kv{display:flex;gap:4px;line-height:1.65;flex-wrap:nowrap}
.kv-key{color:var(--accent);min-width:78px;flex-shrink:0;font-size:12px}
.kv-val{color:var(--text);font-size:12px}
/* colors */
.green{color:var(--green)}.red{color:var(--red)}.yellow{color:var(--yellow)}
.blue{color:var(--blue)}.cyan{color:var(--cyan)}.magenta{color:var(--magenta)}
.orange{color:var(--orange)}.dim{color:var(--dim)}.bold{font-weight:bold}
/* dashboard */
#tab-dashboard .content{display:grid;grid-template-columns:210px 1fr 265px;gap:6px;padding:6px;height:100%}
#dash-left{display:flex;flex-direction:column;gap:6px;overflow:hidden}
#dash-mid{display:flex;flex-direction:column;overflow:hidden;gap:0}
#dash-mid .spark-block{flex:1;margin-bottom:4px}
#dash-right{display:flex;flex-direction:column;gap:6px;overflow:hidden}
#dash-right .panel{display:flex;flex-direction:column;flex:1}
#dash-alerts{flex:1;overflow:hidden;display:flex;flex-direction:column}
#dash-alerts .panel-title{flex-shrink:0}
#alerts-body{flex:1;overflow-y:auto;font-size:11px}
/* traffic */
#tab-traffic .content{display:flex;flex-direction:column;padding:6px;gap:6px;height:100%}
/* security */
#tab-security .content{display:grid;grid-template-columns:1fr 225px;gap:6px;padding:6px;height:100%}
#sec-left{display:flex;flex-direction:column;overflow:hidden}
#sec-left .panel{flex:1;display:flex;flex-direction:column}
#sec-right{display:flex;flex-direction:column;gap:6px;overflow:hidden}
#sec-right #blocklist-panel{flex:1;overflow:auto}
/* domains */
#tab-domains .content{display:grid;grid-template-columns:1fr 205px;gap:6px;padding:6px;height:100%}
#dom-left{display:flex;flex-direction:column;overflow:hidden}
#dom-left .panel{flex:1;display:flex;flex-direction:column}
#dom-right{display:flex;flex-direction:column;overflow:hidden}
#dom-right .panel{flex:1;display:flex;flex-direction:column}
/* performance */
#tab-performance .content{display:grid;grid-template-columns:1fr 220px;gap:6px;padding:6px;height:100%}
#perf-sparks{display:flex;flex-direction:column;overflow:hidden}
#perf-sparks .spark-block{flex:1;margin-bottom:4px}
#perf-summary-wrap{overflow:auto}
/* geo */
#tab-geo .content{display:grid;grid-template-columns:1fr 285px;gap:6px;padding:6px;height:100%}
#geo-left{display:flex;flex-direction:column;overflow:hidden}
#geo-left .panel{flex:1;display:flex;flex-direction:column}
#geo-right{display:flex;flex-direction:column;gap:6px;overflow:hidden}
#geo-right .panel{flex:1;display:flex;flex-direction:column}
/* log */
#tab-log .content{display:flex;flex-direction:column;padding:6px;gap:6px;height:100%}
#log-output{flex:1;overflow-y:auto;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:11px;line-height:1.5}
/* history */
#tab-history .content{display:flex;flex-direction:column;padding:6px;gap:6px;height:100%}
#hist-summary-wrap{flex-shrink:0}
#hist-sparks{flex:1;display:flex;flex-direction:column;gap:4px;overflow:hidden;min-height:0}
#hist-sparks .spark-block{flex:1}
/* modal */
.modal{position:fixed;inset:0;background:#0009;z-index:100;display:flex;align-items:center;justify-content:center}
.modal.hidden{display:none}
.modal-box{background:var(--bg);border:2px solid var(--border);border-radius:6px;padding:16px 20px;width:700px;max-height:90vh;overflow:auto;position:relative}
.modal-title{color:var(--accent);font-size:14px;font-weight:bold;margin-bottom:12px}
.modal-close{position:absolute;top:10px;right:14px;background:none;border:none;color:var(--dim);cursor:pointer;font-size:20px;line-height:1}
.modal-close:hover{color:var(--text)}
.modal-kv{display:grid;grid-template-columns:120px 1fr;gap:2px 8px;font-size:12px}
.modal-kv .k{color:var(--accent)}.modal-kv .v{color:var(--text);word-break:break-all}
.modal-section{margin-top:10px;padding-top:8px;border-top:1px solid var(--border)}
.modal-section-title{color:var(--accent);font-weight:bold;margin-bottom:4px;font-size:11px}
.hdr-line{font-size:11px;color:var(--dim)}.hdr-line span{color:var(--text)}
/* scrollbars */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
/* info bar */
.info-bar{flex-shrink:0;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:4px 10px;font-size:11px;color:var(--dim)}
.info-bar b{color:var(--accent)}
</style>
</head>
<body>
<div id="app">
  <div id="header">
    <div id="header-title">\u26a1 J.A.R.V.I.S. HTTPS PROXY</div>
    <div id="conn-status" class="dim">\u25cf connecting\u2026</div>
  </div>
  <div id="statusbar">loading\u2026</div>
  <div id="tabs">
    <button class="tab-btn active" onclick="switchTab('dashboard')" data-tab="dashboard">1 \U0001F4CA Dashboard</button>
    <button class="tab-btn" onclick="switchTab('traffic')"     data-tab="traffic">2 \U0001F4E1 Traffic</button>
    <button class="tab-btn" onclick="switchTab('security')"    data-tab="security">3 \U0001F6E1 Security</button>
    <button class="tab-btn" onclick="switchTab('domains')"     data-tab="domains">4 \U0001F310 Domains</button>
    <button class="tab-btn" onclick="switchTab('performance')" data-tab="performance">5 \u26a1 Performance</button>
    <button class="tab-btn" onclick="switchTab('geo')"         data-tab="geo">6 \U0001F30D Geo</button>
    <button class="tab-btn" onclick="switchTab('log')"         data-tab="log">7 \U0001F4DC Log</button>
    <button class="tab-btn" onclick="switchTab('history')"     data-tab="history">8 \U0001F4C8 History</button>
  </div>
  <div id="main">

    <!-- ─── DASHBOARD ──────────────────────────────────────────────────────── -->
    <div id="tab-dashboard" class="tab-pane active">
      <div class="content">
        <div id="dash-left">
          <div class="panel"><div class="panel-title">\U0001F4CA OVERVIEW</div><div id="overview-body"></div></div>
          <div class="panel"><div class="panel-title">\U0001F4BE CACHE</div><div id="cache-body"></div></div>
          <div id="dash-alerts" class="panel"><div class="panel-title">\U0001F514 RECENT ALERTS</div><div id="alerts-body"></div></div>
        </div>
        <div id="dash-mid">
          <div class="spark-block"><div class="spark-label" id="lbl-resp">\u26a1 Response Time</div><canvas class="spark" id="spark-resp"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-tcp">\U0001F50C TCP Connect</div><canvas class="spark" id="spark-tcp"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-rps">\U0001F4E1 Requests/sec</div><canvas class="spark" id="spark-rps"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-bw">\U0001F4F6 Bandwidth</div><canvas class="spark" id="spark-bw-up" style="flex:1"></canvas><canvas class="spark" id="spark-bw-dn" style="flex:1"></canvas></div>
        </div>
        <div id="dash-right">
          <div class="panel"><div class="panel-title">\U0001F4E1 Status Codes</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Status</th><th>Count</th><th>Share</th></tr></thead><tbody id="sc-body"></tbody></table></div></div>
          <div class="panel"><div class="panel-title">\U0001F3C6 Top Domains</div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Domain</th><th>Reqs</th><th>ms</th></tr></thead><tbody id="td-body"></tbody></table></div></div>
        </div>
      </div>
    </div>

    <!-- ─── TRAFFIC ────────────────────────────────────────────────────────── -->
    <div id="tab-traffic" class="tab-pane">
      <div class="content" style="display:flex;flex-direction:column;padding:6px;gap:6px;height:100%">
        <div class="info-bar">\U0001F4E1 <b>Live Traffic</b> \u2014 newest first, 50 rows \u2014 click row to inspect &nbsp;|\u00a0 <span class="green">\u25cfSafe</span> <span class="yellow">\u25b2Suspicious</span> <span class="red">\u2716Malicious</span> <span style="color:#ff4444">\u25a0Blocked</span></div>
        <div class="tbl-wrap">
          <table class="tbl"><thead><tr><th>Time</th><th>\U0001F512</th><th>\u26a1</th><th>Method</th><th>Client</th><th>Host</th><th>Status</th><th>Size</th><th>Time</th><th>User-Agent</th></tr></thead>
          <tbody id="traffic-body"></tbody></table>
        </div>
      </div>
    </div>

    <!-- ─── SECURITY ───────────────────────────────────────────────────────── -->
    <div id="tab-security" class="tab-pane">
      <div class="content">
        <div id="sec-left">
          <div class="panel">
            <div class="panel-title" style="color:var(--red)">\U0001F6E1\ufe0f Security Threats</div>
            <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Time</th><th>Level</th><th>IP</th><th>Host</th><th>Reason</th><th>Patterns</th></tr></thead><tbody id="threats-body"></tbody></table></div>
          </div>
        </div>
        <div id="sec-right">
          <div class="panel"><div class="panel-title">\U0001F6E1\ufe0f SUMMARY</div><div id="sec-summary-body"></div></div>
          <div class="panel" id="blocklist-panel"><div class="panel-title">\U0001F6AB Lists</div><div id="blocklist-body" style="font-size:11px"></div></div>
        </div>
      </div>
    </div>

    <!-- ─── DOMAINS ────────────────────────────────────────────────────────── -->
    <div id="tab-domains" class="tab-pane">
      <div class="content">
        <div id="dom-left">
          <div class="panel"><div class="panel-title">\U0001F310 Domain Analytics</div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Domain</th><th>Reqs</th><th>Errors</th><th>Err%</th><th>Avg ms</th><th>Data</th><th>Methods</th></tr></thead><tbody id="dom-body"></tbody></table></div></div>
        </div>
        <div id="dom-right">
          <div class="panel"><div class="panel-title">\U0001F4CA Methods &amp; Codes</div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Method/Code</th><th>Count</th></tr></thead><tbody id="methods-body"></tbody></table></div></div>
        </div>
      </div>
    </div>

    <!-- ─── PERFORMANCE ────────────────────────────────────────────────────── -->
    <div id="tab-performance" class="tab-pane">
      <div class="content">
        <div id="perf-sparks">
          <div class="spark-block"><div class="spark-label" id="lbl-dns">\U0001F50D DNS Latency</div><canvas class="spark" id="sp-dns"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-tcp2">\U0001F50C TCP Connect</div><canvas class="spark" id="sp-tcp"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-ssl">\U0001F512 SSL Handshake</div><canvas class="spark" id="sp-ssl"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-resp2">\u26a1 Response/Tunnel</div><canvas class="spark" id="sp-resp"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-rps2">\U0001F4E1 Requests/sec</div><canvas class="spark" id="sp-rps2"></canvas></div>
        </div>
        <div class="panel" id="perf-summary-wrap"><div class="panel-title">\U0001F4CA SUMMARY</div><div id="perf-summary-body"></div></div>
      </div>
    </div>

    <!-- ─── GEO ────────────────────────────────────────────────────────────── -->
    <div id="tab-geo" class="tab-pane">
      <div class="content">
        <div id="geo-left">
          <div class="panel"><div class="panel-title">\U0001F30D Geographic Breakdown</div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>\U0001F30D Country</th><th>Requests</th><th>Share</th></tr></thead><tbody id="geo-body"></tbody></table></div></div>
        </div>
        <div id="geo-right">
          <div class="panel"><div class="panel-title">\U0001F4C4 Content Types</div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Type</th><th>Count</th><th>%</th></tr></thead><tbody id="ct-body"></tbody></table></div></div>
          <div class="panel"><div class="panel-title">\U0001F465 Top Clients</div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Client IP</th><th>Requests</th></tr></thead><tbody id="cli-body"></tbody></table></div></div>
        </div>
      </div>
    </div>

    <!-- ─── LOG ────────────────────────────────────────────────────────────── -->
    <div id="tab-log" class="tab-pane">
      <div class="content" style="display:flex;flex-direction:column;padding:6px;gap:6px;height:100%">
        <div class="info-bar">\U0001F4DC <b>LIVE LOG</b> \u2014 auto-scroll &nbsp;|\u00a0 <span class="green">\u25cfSafe</span> <span class="yellow">\u25b2Suspicious</span> <span class="red">\u2716Malicious</span> <span style="color:#ff4444">\u25a0Blocked</span></div>
        <div id="log-output"></div>
      </div>
    </div>

    <!-- ─── HISTORY ────────────────────────────────────────────────────────── -->
    <div id="tab-history" class="tab-pane">
      <div class="content" style="display:flex;flex-direction:column;padding:6px;gap:6px;height:100%">
        <div class="panel" id="hist-summary-wrap"><div class="panel-title">\U0001F4C8 HISTORICAL OVERVIEW</div><div id="hist-summary-body" style="display:flex;flex-wrap:wrap;gap:0 24px"></div></div>
        <div id="hist-sparks">
          <div class="spark-block"><div class="spark-label" id="lbl-min-rps">\U0001F4E1 Req/min</div><canvas class="spark" id="sp-min-rps"></canvas></div>
          <div class="spark-block"><div class="spark-label" id="lbl-hr-rps">\U0001F550 Req/hr</div><canvas class="spark" id="sp-hr-rps"></canvas></div>
        </div>
      </div>
    </div>

  </div><!-- #main -->
</div><!-- #app -->

<!-- ─── REQUEST INSPECTOR MODAL ──────────────────────────────────────────── -->
<div id="modal" class="modal hidden" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal()">\u2715</button>
    <div class="modal-title">\U0001F50D Request Inspector</div>
    <div id="modal-content"></div>
  </div>
</div>

<script>
// ── state ─────────────────────────────────────────────────────────────────────
let D = {};
let activeTab = 'dashboard';
let logWritten = 0;
let trafficRows = [];

// ── SSE connection ────────────────────────────────────────────────────────────
function connect() {
  const cs = document.getElementById('conn-status');
  const es = new EventSource('/events');
  es.onopen  = () => { cs.textContent = '\u25cf live'; cs.style.color = 'var(--green)'; };
  es.onerror = () => { cs.textContent = '\u25cf disconnected'; cs.style.color = 'var(--red)'; es.close(); setTimeout(connect, 3000); };
  es.onmessage = e => { D = JSON.parse(e.data); renderStatusBar(); renderActiveTab(); };
}
connect();

// ── tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.querySelector('[data-tab="' + tab + '"]').classList.add('active');
  activeTab = tab;
  renderActiveTab();
}
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
  const map = {'1':'dashboard','2':'traffic','3':'security','4':'domains','5':'performance','6':'geo','7':'log','8':'history'};
  if (map[e.key]) switchTab(map[e.key]);
  if (e.key === 'Escape') closeModal();
});
function renderActiveTab() {
  if (!D || D.total_requests === undefined) return;
  ({dashboard:renderDashboard,traffic:renderTraffic,security:renderSecurity,
    domains:renderDomains,performance:renderPerformance,
    geo:renderGeo,log:renderLog,history:renderHistory}[activeTab] || (()=>{}))();
}

// ── formatting ────────────────────────────────────────────────────────────────
function fmtBytes(n) {
  if (!n || n < 0) return '0 B';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + '\u00a0' + u[i];
}
function fmtMs(ms) {
  if (!ms) return '--';
  if (ms < 1)    return (ms * 1000).toFixed(0) + '\u03bcs';
  if (ms < 1000) return ms.toFixed(1) + 'ms';
  return (ms / 1000).toFixed(2) + 's';
}
function fmtDur(s) {
  if (s < 60)    return s.toFixed(0) + 's';
  if (s < 3600)  return (s / 60).toFixed(1) + 'm';
  if (s < 86400) return (s / 3600).toFixed(1) + 'h';
  return (s / 86400).toFixed(1) + 'd';
}
function scColor(code) {
  if (!code)      return 'var(--text)';
  if (code < 300) return 'var(--green)';
  if (code < 400) return 'var(--yellow)';
  if (code < 500) return 'var(--orange)';
  return 'var(--red)';
}
function threatColor(l) {
  return {safe:'var(--green)',suspicious:'var(--yellow)',malicious:'var(--red)',blocked:'#ff4444'}[l]||'var(--text)';
}
function threatIcon(l) {
  return {safe:'\u25cf',suspicious:'\u25b2',malicious:'\u2716',blocked:'\u25a0'}[l]||'?';
}
function bar(pct, w) {
  w = w || 16; const f = Math.max(0, Math.min(w, Math.round(pct / 100 * w)));
  return '\u2588'.repeat(f) + '\u2591'.repeat(w - f);
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function kv(key, valHtml) {
  return '<div class="kv"><span class="kv-key">' + key + '</span><span class="kv-val">' + valHtml + '</span></div>';
}
function avg(a) { return a && a.length ? a.reduce((x,y)=>x+y,0)/a.length : 0; }

// ── sparkline renderer ────────────────────────────────────────────────────────
function drawSpark(id, data, minColor, maxColor) {
  minColor = minColor || '#00cc44'; maxColor = maxColor || '#ff3333';
  const el = document.getElementById(id); if (!el) return;
  const w = el.offsetWidth; const h = el.offsetHeight;
  if (!w || !h) return;
  el.width = w; el.height = h;
  const ctx = el.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  if (!data || !data.length) data = [0];
  const mn = Math.min(...data), mx = Math.max(...data), range = mx - mn || 1;
  const pts = data.map((v, i) => ({
    x: data.length === 1 ? w/2 : i / (data.length - 1) * w,
    y: h - 2 - ((v - mn) / range) * (h - 4)
  }));
  // gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, minColor + '55'); grad.addColorStop(1, minColor + '08');
  ctx.beginPath();
  pts.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
  ctx.lineTo(pts[pts.length-1].x, h); ctx.lineTo(pts[0].x, h); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
  // line — color based on last value relative to range
  const pct = range ? (data[data.length-1] - mn) / range : 0;
  function hexToRgb(hex) { return [1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)); }
  const [r1,g1,b1] = hexToRgb(minColor), [r2,g2,b2] = hexToRgb(maxColor);
  const lc = `rgb(${Math.round(r1+(r2-r1)*pct)},${Math.round(g1+(g2-g1)*pct)},${Math.round(b1+(b2-b1)*pct)})`;
  ctx.beginPath();
  pts.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
  ctx.strokeStyle = lc; ctx.lineWidth = 1.5; ctx.stroke();
}

// ── STATUS BAR ────────────────────────────────────────────────────────────────
function renderStatusBar() {
  if (!D || D.total_requests === undefined) return;
  const ct = D.cache_hits + D.cache_misses;
  const hr = ct ? (D.cache_hits / ct * 100).toFixed(0) : 0;
  document.getElementById('statusbar').innerHTML =
    '<span style="color:var(--cyan)">\u26a1 ' + D.rps.toFixed(1) + ' req/s</span>' +
    ' | <span style="color:var(--yellow)">\U0001F517 ' + D.active_connections + ' active</span>' +
    ' | <span>\U0001F4CA ' + D.total_requests.toLocaleString() + ' total</span>' +
    ' | <span style="color:var(--green)">\u2191' + fmtBytes(D.current_upload_bps) + '/s</span>' +
    '\u00a0<span style="color:var(--blue)">\u2193' + fmtBytes(D.current_download_bps) + '/s</span>' +
    ' | <span style="color:var(--magenta)">\U0001F4BE ' + hr + '% cache</span>' +
    ' | <span>\u26a1 ' + fmtMs(D.avg_resp) + '</span>' +
    ' | <span style="color:var(--red)">\U0001F6E1 ' + D.threats_blocked + ' blocked</span>' +
    ' | <span class="dim">\u23f1 ' + fmtDur(D.uptime) + '</span>' +
    (D.ssl_inspection ? ' | <span style="color:var(--green)">\U0001F512SSL</span>' : '') +
    (D.whitelist_mode ? ' | <span style="color:var(--cyan)">\U0001F4CBWL</span>' : '');
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function renderDashboard() {
  const s = D;
  const okPct  = s.total_requests ? ((s.total_requests - s.total_errors) / s.total_requests * 100).toFixed(1) : '100.0';
  const httpsP = s.total_requests ? (s.https_requests / s.total_requests * 100).toFixed(0) : 0;
  const ct     = s.cache_hits + s.cache_misses;
  const hr     = ct ? (s.cache_hits / ct * 100).toFixed(1) : '0.0';
  document.getElementById('overview-body').innerHTML =
    kv('Requests', s.total_requests.toLocaleString() + ' <span class="red">err ' + s.total_errors.toLocaleString() + '</span>') +
    kv('Success',  '<span class="green">' + okPct + '%</span> <span class="dim">' + s.rps.toFixed(1) + ' req/s</span>') +
    kv('HTTPS',    '<span class="green">' + s.https_requests.toLocaleString() + '</span> <span class="dim">(' + httpsP + '%)</span>') +
    kv('HTTP',     '<span class="blue">'  + s.http_requests.toLocaleString()  + '</span>') +
    kv('Active',   '<span class="yellow">' + s.active_connections + '</span> peak <span class="yellow">' + s.peak_connections + '</span>') +
    kv('Clients',  s.unique_clients.toLocaleString()) +
    kv('DNS avg',  fmtMs(avg(s.dns_times))) +
    kv('Resp avg', fmtMs(avg(s.response_times))) +
    kv('\u2191 Sent',   '<span class="green">'  + fmtBytes(s.total_bytes_sent)     + '</span> <span class="dim">' + fmtBytes(s.current_upload_bps)   + '/s</span>') +
    kv('\u2193 Recv',   '<span class="blue">'   + fmtBytes(s.total_bytes_received) + '</span> <span class="dim">' + fmtBytes(s.current_download_bps) + '/s</span>');

  document.getElementById('cache-body').innerHTML =
    kv('Hits',    '<span class="green">' + s.cache_hits.toLocaleString()   + '</span>') +
    kv('Misses',  '<span class="red">'   + s.cache_misses.toLocaleString() + '</span>') +
    kv('Rate',    '<span class="blue">'  + hr + '%</span>') +
    '<div class="kv"><span class="kv-key"></span><span style="color:var(--blue);letter-spacing:-1px">' + bar(parseFloat(hr)) + '</span></div>' +
    kv('Entries', s.cache_entries.toLocaleString()) +
    kv('Threats', '<span class="red">' + s.threats_blocked.toLocaleString() + '</span> <span class="dim">' + s.malicious_ips + ' IPs</span>');

  const alertColors = {SYSTEM:'var(--cyan)',SECURITY:'var(--red)',TUI:'var(--magenta)'};
  const alerts = (s.alerts || []).slice().reverse().slice(0, 8);
  document.getElementById('alerts-body').innerHTML = alerts.length
    ? alerts.map(a => '<div class="kv" style="font-size:11px"><span class="dim">' + esc(a.time) + '</span>&nbsp;<span style="color:' + (alertColors[a.type]||'var(--text)') + '">' + esc(a.type) + '</span>&nbsp;' + esc(a.message) + '</div>').join('')
    : '<span class="dim">No alerts</span>';

  // sparklines
  const rd = s.response_times.length ? s.response_times : [0];
  const td = s.tcp_times.length      ? s.tcp_times      : [0];
  const rp = s.rps_history.length    ? s.rps_history    : [0];
  const up = s.upload_bps_history.length   ? s.upload_bps_history   : [0];
  const dn = s.download_bps_history.length ? s.download_bps_history : [0];
  drawSpark('spark-resp', rd);
  drawSpark('spark-tcp',  td);
  drawSpark('spark-rps',  rp, '#0088ff', '#00ffff');
  drawSpark('spark-bw-up', up, '#00cc44', '#00ff88');
  drawSpark('spark-bw-dn', dn, '#ff8800', '#ffcc00');
  document.getElementById('lbl-resp').innerHTML = '\u26a1 Response Time \u00a0<span class="dim">avg <span class="yellow">' + fmtMs(avg(rd)) + '</span> max <span class="red">' + fmtMs(Math.max(...rd)) + '</span></span>';
  document.getElementById('lbl-tcp').innerHTML  = '\U0001F50C TCP Connect \u00a0<span class="dim">avg <span class="yellow">' + fmtMs(avg(td)) + '</span> max <span class="red">' + fmtMs(Math.max(...td)) + '</span></span>';
  document.getElementById('lbl-rps').innerHTML  = '\U0001F4E1 Req/sec \u00a0<span class="dim">avg <span class="cyan">' + avg(rp).toFixed(1) + '</span> peak <span class="cyan">' + Math.max(...rp).toFixed(1) + '</span></span>';
  document.getElementById('lbl-bw').innerHTML   = '\U0001F4F6 Bandwidth \u00a0<span class="dim"><span class="green">\u2191' + fmtBytes(s.current_upload_bps) + '/s</span> <span class="yellow">\u2193' + fmtBytes(s.current_download_bps) + '/s</span></span>';

  // status codes
  const totalSc = Object.values(s.status_codes).reduce((a,b)=>a+b,0);
  document.getElementById('sc-body').innerHTML =
    Object.entries(s.status_codes).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([code, cnt]) => {
      const pct = totalSc ? cnt/totalSc*100 : 0; const c = scColor(+code);
      return '<tr><td style="color:' + c + '">' + code + '</td><td>' + cnt.toLocaleString() + '</td><td style="color:' + c + '">' + bar(pct, 10) + ' ' + pct.toFixed(0) + '%</td></tr>';
    }).join('');

  // top domains
  document.getElementById('td-body').innerHTML =
    Object.entries(s.domain_stats).sort((a,b)=>b[1].requests-a[1].requests).slice(0,10)
      .map(([d, ds]) => '<tr><td>' + esc(d.slice(0,30)) + '</td><td>' + ds.requests.toLocaleString() + '</td><td>' + fmtMs(ds.avg_time) + '</td></tr>').join('');
}

// ── TRAFFIC ───────────────────────────────────────────────────────────────────
function renderTraffic() {
  trafficRows = D.recent_requests || [];
  document.getElementById('traffic-body').innerHTML = trafficRows.map((r, i) => {
    const lc  = threatColor(r.security_level);
    const sec = '<span style="color:' + lc + '">' + threatIcon(r.security_level) + '</span>';
    const lock = r.is_https ? '\U0001F512' : '';
    let st;
    if (r.error)           st = '<span class="red">ERR</span>';
    else if (r.status_code) st = '<span style="color:' + scColor(r.status_code) + '">' + r.status_code + '</span>';
    else                   st = '<span class="dim">\u2014</span>';
    const size = r.cached ? '<span class="blue">\U0001F4BE' + fmtBytes(r.body_bytes) + '</span>' : (r.body_bytes ? fmtBytes(r.body_bytes) : '\u2014');
    const rt   = r.response_time_ms ? fmtMs(r.response_time_ms) : '<span class="dim">\u2014</span>';
    const host = r.error ? '<span class="red">' + esc(r.host.slice(0,32)) + '</span>' : esc(r.host.slice(0,32));
    return '<tr class="clickable" onclick="openModal(' + i + ')">' +
      '<td>' + esc(r.ts) + '</td><td>' + lock + '</td><td>' + sec + '</td>' +
      '<td>' + esc(r.method.slice(0,6)) + '</td><td class="dim">' + esc(r.client_ip) + '</td>' +
      '<td>' + host + '</td><td>' + st + '</td><td>' + size + '</td><td>' + rt + '</td>' +
      '<td class="dim">' + esc((r.user_agent||'').slice(0,30)) + '</td></tr>';
  }).join('');
}

// ── MODAL ─────────────────────────────────────────────────────────────────────
function openModal(i) {
  const r = trafficRows[i]; if (!r) return;
  const sc   = r.status_code ? '<span style="color:' + scColor(r.status_code) + '">' + r.status_code + '</span>' : '\u2014';
  const secc = threatColor(r.security_level);
  const lock = r.is_https ? '\U0001F512 HTTPS' : '\U0001F513 HTTP';
  const dns  = r.dns || {};
  let geo = '';
  if (r.geo_location) {
    const g = r.geo_location;
    geo = '<div class="k">Country</div><div class="v">' + esc(g.country) + ' <span class="dim">' + esc(g.city) + '</span></div>' +
          '<div class="k">ISP</div><div class="v">' + esc(g.isp) + '</div>' +
          (g.is_vpn ? '<div class="k"></div><div class="v yellow">\u26a0 VPN/Proxy detected</div>' : '');
  }
  let ssl = r.ssl_info ? '<div class="k">TLS</div><div class="v">' + esc(r.ssl_info.protocol) + ' <span class="dim">' + esc(r.ssl_info.cipher) + '</span></div>' : '';
  let reqH = '', respH = '';
  if (r.request_headers && Object.keys(r.request_headers).length) {
    reqH = '<div class="modal-section"><div class="modal-section-title">Request Headers</div><div class="hdr-line">' +
      Object.entries(r.request_headers).slice(0,8).map(([k,v]) => '<div><span>' + esc(k) + ':</span> ' + esc(v) + '</div>').join('') + '</div></div>';
  }
  if (r.response_headers && Object.keys(r.response_headers).length) {
    respH = '<div class="modal-section"><div class="modal-section-title">Response Headers</div><div class="hdr-line">' +
      Object.entries(r.response_headers).slice(0,8).map(([k,v]) => '<div><span>' + esc(k) + ':</span> ' + esc(v) + '</div>').join('') + '</div></div>';
  }
  document.getElementById('modal-content').innerHTML =
    '<div class="modal-kv">' +
    '<div class="k">Timestamp</div><div class="v">' + esc(r.timestamp) + '</div>' +
    '<div class="k">Type</div><div class="v">' + esc(r.method) + ' ' + lock + (r.cached ? ' <span class="blue">\U0001F4BE CACHED</span>' : '') + (r.compressed ? ' <span class="dim">(gzip)</span>' : '') + '</div>' +
    '<div class="k">Client</div><div class="v">' + esc(r.client_ip) + '</div>' +
    '<div class="k">Host</div><div class="v"><b>' + esc(r.host) + ':' + r.port + '</b></div>' +
    '<div class="k">URL</div><div class="v dim">' + esc((r.url||'\u2014').slice(0,120)) + '</div>' +
    '<div class="k">Status</div><div class="v">' + sc + '</div>' +
    '<div class="k">Body</div><div class="v">' + fmtBytes(r.body_bytes||0) + '</div>' +
    '<div class="k">Resp Time</div><div class="v">' + fmtMs(r.response_time_ms||0) + '</div>' +
    '<div class="k">TCP ms</div><div class="v">' + fmtMs(r.tcp_connect_ms) + '</div>' +
    '<div class="k">DNS ms</div><div class="v">' + fmtMs(dns.dns_time_ms) + ' <span class="dim">cached=' + dns.cached + ' ipv6=' + dns.is_ipv6 + '</span></div>' +
    '<div class="k">DNS IPs</div><div class="v dim">' + esc((dns.addresses||[]).join(', ')) + '</div>' +
    '<div class="k">Security</div><div class="v" style="color:' + secc + '">' + r.security_level.toUpperCase() + '</div>' +
    '<div class="k">UA</div><div class="v dim">' + esc((r.user_agent||'\u2014').slice(0,100)) + '</div>' +
    geo + ssl +
    (r.error ? '<div class="k">Error</div><div class="v red">' + esc(r.error) + '</div>' : '') +
    '</div>' + reqH + respH;
  document.getElementById('modal').classList.remove('hidden');
}
function closeModal() { document.getElementById('modal').classList.add('hidden'); }

// ── SECURITY ──────────────────────────────────────────────────────────────────
function renderSecurity() {
  const labels = {safe:['SAFE','var(--green)'],suspicious:['SUSPECT','var(--yellow)'],malicious:['MALICIOUS','var(--red)'],blocked:['BLOCKED','#ff4444']};
  const threats = (D.security_threats||[]);
  document.getElementById('threats-body').innerHTML =
    (threats.length ? threats : [{level:'safe',timestamp:'',ip:'',host:'No threats detected',reason:'',patterns:[]}]).map(t => {
      const [lbl, lc] = labels[t.level] || [t.level, 'var(--text)'];
      const ts = (t.timestamp||'').slice(11,19)||'\u2014';
      return '<tr><td>' + ts + '</td><td style="color:' + lc + '">' + lbl + '</td><td class="dim">' + esc(t.ip) + '</td><td>' + esc((t.host||'').slice(0,26)) + '</td><td class="dim">' + esc((t.reason||'').slice(0,34)) + '</td><td class="dim">' + esc((t.patterns||[]).join(', ').slice(0,24)) + '</td></tr>';
    }).join('');

  const wl = D.whitelist_mode ? '<span class="green">ON</span>' : '<span class="dim">off</span>';
  document.getElementById('sec-summary-body').innerHTML =
    kv('Blocked',   '<span class="red">' + (D.threats_blocked||0).toLocaleString() + '</span>') +
    kv('Mal. IPs',  '<span class="red">' + (D.malicious_ips||0) + '</span>') +
    kv('Threats',   (D.security_threats||[]).length) +
    kv('Whitelist', wl) +
    kv('Blocked',   (D.blocked_domains||[]).length + ' domains') +
    kv('Allowed',   (D.allowed_domains||[]).length + ' domains');

  const bk = (D.blocked_domains||[]).map(d=>'<div><span class="red">\u2717</span> '+esc(d)+'</div>').join('')||'<span class="dim">(none)</span>';
  const al = (D.allowed_domains||[]).map(d=>'<div><span class="green">\u2713</span> '+esc(d)+'</div>').join('')||'<span class="dim">(none)</span>';
  document.getElementById('blocklist-body').innerHTML =
    '<div style="color:var(--accent);font-weight:bold;margin-bottom:4px">\U0001F6AB Blocklist</div>' + bk +
    '<div style="color:var(--accent);font-weight:bold;margin:8px 0 4px">\u2705 Allowlist ' + wl + '</div>' + al;
}

// ── DOMAINS ───────────────────────────────────────────────────────────────────
function renderDomains() {
  document.getElementById('dom-body').innerHTML =
    Object.entries(D.domain_stats||{}).sort((a,b)=>b[1].requests-a[1].requests).slice(0,45).map(([d,ds]) => {
      const ep = ds.requests ? (ds.errors/ds.requests*100).toFixed(0) : 0;
      const meth = Object.entries(ds.methods||{}).slice(0,2).map(([m,c])=>m+':'+c).join(' ');
      return '<tr><td>' + esc(d.slice(0,38)) + '</td><td>' + ds.requests.toLocaleString() + '</td><td>' + ds.errors.toLocaleString() + '</td><td>' + ep + '%</td><td>' + fmtMs(ds.avg_time) + '</td><td>' + fmtBytes(ds.bytes) + '</td><td class="dim">' + esc(meth.slice(0,18)) + '</td></tr>';
    }).join('');

  document.getElementById('methods-body').innerHTML =
    '<tr><td colspan="2" style="color:var(--accent);font-weight:bold">\u2500\u2500 Methods \u2500\u2500</td></tr>' +
    Object.entries(D.methods||{}).map(([m,c]) => '<tr><td style="color:var(--cyan)">' + esc(m) + '</td><td>' + c.toLocaleString() + '</td></tr>').join('') +
    '<tr><td colspan="2" style="color:var(--accent);font-weight:bold">\u2500\u2500 Codes \u2500\u2500\u2500\u2500</td></tr>' +
    Object.entries(D.status_codes||{}).sort((a,b)=>b[1]-a[1]).slice(0,12).map(([code,cnt]) =>
      '<tr><td style="color:' + scColor(+code) + '">' + code + '</td><td>' + cnt.toLocaleString() + '</td></tr>').join('');
}

// ── PERFORMANCE ───────────────────────────────────────────────────────────────
function renderPerformance() {
  function upd(sid, lid, label, vals) {
    const data = vals && vals.length ? vals : [0];
    drawSpark(sid, data);
    const a = avg(data), mx = Math.max(...data);
    document.getElementById(lid).innerHTML = label + ' \u00a0<span class="dim">avg <span class="yellow">' + fmtMs(a) + '</span> max <span class="red">' + fmtMs(mx) + '</span> n=' + data.length + '</span>';
  }
  upd('sp-dns',  'lbl-dns',   '\U0001F50D DNS Latency',    D.dns_times);
  upd('sp-tcp',  'lbl-tcp2',  '\U0001F50C TCP Connect',    D.tcp_times);
  upd('sp-ssl',  'lbl-ssl',   '\U0001F512 SSL Handshake',  D.ssl_times);
  upd('sp-resp', 'lbl-resp2', '\u26a1 Response/Tunnel',       D.response_times);
  const rp = D.rps_history.length ? D.rps_history : [0];
  drawSpark('sp-rps2', rp, '#0088ff', '#00ffff');
  document.getElementById('lbl-rps2').innerHTML = '\U0001F4E1 Requests/sec \u00a0<span class="dim">avg <span class="cyan">' + avg(rp).toFixed(1) + '</span> peak <span class="cyan">' + Math.max(...rp).toFixed(1) + '</span></span>';

  const up = D.uptime, tb = D.total_bytes_sent + D.total_bytes_received;
  const ct = D.cache_hits + D.cache_misses;
  document.getElementById('perf-summary-body').innerHTML =
    kv('Uptime',     fmtDur(up)) +
    kv('Total Reqs', D.total_requests.toLocaleString()) +
    kv('BW/s',       fmtBytes(up > 0 ? tb/up : 0) + '/s') +
    kv('Total BW',   fmtBytes(tb)) +
    kv('Peak Conn',  '<span class="yellow">' + D.peak_connections + '</span>') +
    kv('Clients',    D.unique_clients.toLocaleString()) +
    kv('Cache Rate', '<span class="blue">' + (ct ? (D.cache_hits/ct*100).toFixed(1) : '\u2014') + '%</span>');
}

// ── GEO ───────────────────────────────────────────────────────────────────────
function renderGeo() {
  const geo = D.geo_stats||{}, tg = Object.values(geo).reduce((a,b)=>a+b,0);
  document.getElementById('geo-body').innerHTML =
    Object.entries(geo).map(([c,n]) => {
      const p = tg ? n/tg*100 : 0;
      return '<tr><td>' + esc(c) + '</td><td>' + n.toLocaleString() + '</td><td style="color:var(--cyan);letter-spacing:-1px">' + bar(p,18) + ' ' + p.toFixed(1) + '%</td></tr>';
    }).join('') || '<tr><td colspan="3" class="dim">No data yet</td></tr>';

  const ct = D.content_types||{}, tc = Object.values(ct).reduce((a,b)=>a+b,0);
  document.getElementById('ct-body').innerHTML =
    Object.entries(ct).map(([t,n]) => '<tr><td>' + esc(t.toUpperCase()) + '</td><td>' + n.toLocaleString() + '</td><td>' + (tc ? (n/tc*100).toFixed(0) : 0) + '%</td></tr>').join('') || '<tr><td colspan="3" class="dim">No data</td></tr>';

  document.getElementById('cli-body').innerHTML =
    Object.entries(D.client_requests||{}).map(([ip,n]) => '<tr><td>' + esc(ip) + '</td><td>' + n.toLocaleString() + '</td></tr>').join('') || '<tr><td colspan="2" class="dim">No data</td></tr>';
}

// ── LOG ───────────────────────────────────────────────────────────────────────
function renderLog() {
  const lines = D.log_lines||[], total = D.log_total||0;
  if (total <= logWritten) return;
  const out = document.getElementById('log-output');
  const atBottom = out.scrollHeight - out.clientHeight - out.scrollTop < 60;
  const newLines = lines.slice(Math.max(0, lines.length - (total - logWritten)));
  const cols = {safe:'var(--green)',suspicious:'var(--yellow)',malicious:'var(--red)',blocked:'#ff4444'};
  const frag = document.createDocumentFragment();
  newLines.forEach(([ts, sec, msg]) => {
    const d = document.createElement('div');
    d.innerHTML = '<span class="dim">' + esc(ts) + '</span> <span style="color:' + (cols[sec]||'var(--text)') + '">\u25cf</span> ' + esc(msg);
    frag.appendChild(d);
  });
  out.appendChild(frag);
  logWritten = total;
  while (out.children.length > 3000) out.removeChild(out.firstChild);
  if (atBottom) out.scrollTop = out.scrollHeight;
}

// ── HISTORY ───────────────────────────────────────────────────────────────────
function renderHistory() {
  const s = D, tb = s.total_bytes_sent + s.total_bytes_received;
  document.getElementById('hist-summary-body').innerHTML =
    kv('Total Reqs', s.total_requests.toLocaleString()) +
    kv('Errors',     '<span class="red">' + s.total_errors.toLocaleString() + '</span>') +
    kv('Bandwidth',  fmtBytes(tb)) +
    kv('Clients',    s.unique_clients.toLocaleString()) +
    kv('Domains',    Object.keys(s.domain_stats||{}).length.toLocaleString());

  const mn = s.minute_history.length ? s.minute_history : [0];
  drawSpark('sp-min-rps', mn, '#0088ff', '#00ffff');
  document.getElementById('lbl-min-rps').innerHTML = '\U0001F4E1 Req/min \u2014 last ' + mn.length + ' minutes \u00a0<span class="dim">avg <span class="cyan">' + avg(mn).toFixed(0) + '</span> peak <span class="cyan">' + Math.max(...mn).toFixed(0) + '</span></span>';

  const hr = s.hour_history.length ? s.hour_history : [0];
  drawSpark('sp-hr-rps', hr, '#00cc44', '#ff8800');
  document.getElementById('lbl-hr-rps').innerHTML = '\U0001F550 Req/hr \u2014 last ' + hr.length + ' hours \u00a0<span class="dim">avg <span class="green">' + avg(hr).toFixed(0) + '</span> peak <span class="green">' + Math.max(...hr).toFixed(0) + '</span></span>';
}
</script>
</body>
</html>"""


# ── server ────────────────────────────────────────────────────────────────────

class WebUIServer:
    """Async HTTP + SSE server that mirrors the Textual TUI as a web dashboard."""

    def __init__(self, proxy: "JARVISProxy", host: str = "0.0.0.0", port: int = 8890):
        self.proxy = proxy
        self.host  = host
        self.port  = port
        self._sse_queues: Set[asyncio.Queue] = set()
        self._rps_history: deque = deque(maxlen=60)
        self._last_count = 0
        self._last_tick  = time.time()
        self._html_bytes = _HTML.encode()
        # Optional token auth — empty string means open access
        import config as _cfg
        self._token: str = _cfg.get("web_ui", "token", "") or ""

    async def start(self) -> asyncio.AbstractServer:
        ssl_ctx: ssl.SSLContext | None = None
        import config as _cfg2
        _tls = _cfg2.load().get("web_ui", {}).get("tls", {})
        if _tls.get("enabled", False):
            cert = _tls.get("cert", "")
            key  = _tls.get("key", "")
            if cert and key:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(cert, key)
                log.info("Web UI TLS enabled (cert=%s)", cert)
            else:
                # Auto-generate self-signed cert via ssl_manager if present
                try:
                    from ssl_manager import SSLCertificateManager
                    _mgr = SSLCertificateManager()
                    _cert_path, _key_path = _mgr.get_ca_cert_path(), _mgr.get_ca_key_path()
                    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_ctx.load_cert_chain(_cert_path, _key_path)
                    log.info("Web UI TLS: using proxy CA cert")
                except Exception as exc:
                    log.warning("Web UI TLS requested but cert load failed: %s", exc)

        server = await asyncio.start_server(
            self._handle, self.host, self.port,
            reuse_address=True,
            ssl=ssl_ctx,
        )
        scheme = "https" if ssl_ctx else "http"
        asyncio.create_task(self._broadcast_loop())
        log.info("Web UI at %s://%s:%d", scheme, self.host, self.port)
        return server

    # ── auth helper ───────────────────────────────────────────────────────────

    def _is_authorised(self, headers: dict) -> bool:
        """Return True if auth is disabled or the request carries a valid token."""
        if not self._token:
            return True
        # Bearer token in Authorization header
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip() == self._token
        # Token in X-API-Key header
        if headers.get("x-api-key", "") == self._token:
            return True
        return False

    # ── request router ────────────────────────────────────────────────────────

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=10)
            parts = raw.decode(errors="ignore").strip().split()
            if len(parts) < 2:
                return
            method = parts[0]
            path = parts[1].split("?")[0]
            # drain and parse headers
            req_headers: dict = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
                decoded = line.decode(errors="ignore").strip()
                if ": " in decoded:
                    k, _, v = decoded.partition(": ")
                    req_headers[k.lower()] = v

            # ── auth gate ─────────────────────────────────────────────────────
            if path not in ("/", "/index.html") and not self._is_authorised(req_headers):
                writer.write(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"WWW-Authenticate: Bearer realm=\"JARVIS\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            # ── routing ───────────────────────────────────────────────────────
            if path in ("/", "/index.html"):
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\n"
                    + f"Content-Length: {len(self._html_bytes)}\r\n\r\n".encode()
                    + self._html_bytes
                )
                await writer.drain()
            elif path == "/events":
                if not self._is_authorised(req_headers):
                    writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
                await self._serve_sse(writer)
                return  # SSE is long-lived; don't close below
            elif path == "/api/stats":
                body = json.dumps(self._payload(), separators=(",", ":")).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            elif path == "/metrics":
                body = self._prometheus_metrics().encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; version=0.0.4\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            elif path == "/api/v1/status":
                body = json.dumps(self._v1_status(), separators=(",", ":")).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            elif path == "/api/v1/cache/flush" and method == "POST":
                import asyncio as _aio
                _aio.create_task(self._flush_cache())
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            elif path.startswith("/api/v1/block"):
                await self._handle_block_api(method, path, reader, writer)
            elif path == "/api/v1/har":
                await self._handle_har_export(writer)
            elif path == "/openapi.yaml":
                await self._serve_openapi_spec(writer)
            elif path == "/docs":
                # Redirect to Swagger UI (CDN-hosted) pointing at our spec
                import urllib.parse as _uparse
                spec_url = f"http://{req_headers.get('host', 'localhost')}/openapi.yaml"
                sw_url   = f"https://petstore.swagger.io/?url={_uparse.quote(spec_url)}"
                writer.write(
                    f"HTTP/1.1 302 Found\r\nLocation: {sw_url}\r\nContent-Length: 0\r\n\r\n".encode()
                )
                await writer.drain()
            # ── Extended management API ──────────────────────────────────────
            elif path == "/api/v1/blocklist":
                await self._handle_blocklist(method, reader, writer)
            elif path.startswith("/api/v1/blocklist/"):
                domain = path[len("/api/v1/blocklist/"):]
                await self._handle_blocklist_item(method, domain, writer)
            elif path == "/api/v1/allowlist":
                await self._handle_allowlist(method, reader, writer)
            elif path.startswith("/api/v1/allowlist/"):
                domain = path[len("/api/v1/allowlist/"):]
                await self._handle_allowlist_item(method, domain, writer)
            elif path == "/api/v1/filters":
                await self._handle_filters_config(method, reader, writer)
            elif path == "/api/v1/security":
                await self._handle_security_config(method, reader, writer)
            elif path == "/api/v1/bandwidth":
                await self._handle_bandwidth_api(method, reader, writer)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Prometheus /metrics ───────────────────────────────────────────────────

    def _prometheus_metrics(self) -> str:
        s = self.proxy.stats
        cache = self.proxy.cache.get_stats()
        uptime = time.time() - s.start_time
        lines = [
            "# HELP jarvis_requests_total Total number of proxy requests",
            "# TYPE jarvis_requests_total counter",
            f"jarvis_requests_total {s.total_requests}",
            "# HELP jarvis_errors_total Total number of proxy errors",
            "# TYPE jarvis_errors_total counter",
            f"jarvis_errors_total {s.total_errors}",
            "# HELP jarvis_threats_blocked_total Threats blocked",
            "# TYPE jarvis_threats_blocked_total counter",
            f"jarvis_threats_blocked_total {s.threats_blocked}",
            "# HELP jarvis_cache_hits_total Cache hits",
            "# TYPE jarvis_cache_hits_total counter",
            f"jarvis_cache_hits_total {s.cache_hits}",
            "# HELP jarvis_cache_misses_total Cache misses",
            "# TYPE jarvis_cache_misses_total counter",
            f"jarvis_cache_misses_total {s.cache_misses}",
            "# HELP jarvis_bytes_sent_total Bytes sent to clients",
            "# TYPE jarvis_bytes_sent_total counter",
            f"jarvis_bytes_sent_total {s.total_bytes_sent}",
            "# HELP jarvis_bytes_received_total Bytes received from upstream",
            "# TYPE jarvis_bytes_received_total counter",
            f"jarvis_bytes_received_total {s.total_bytes_received}",
            "# HELP jarvis_active_connections Current active connections",
            "# TYPE jarvis_active_connections gauge",
            f"jarvis_active_connections {s.active_connections}",
            "# HELP jarvis_cache_entries Current cache entry count",
            "# TYPE jarvis_cache_entries gauge",
            f"jarvis_cache_entries {cache['entries']}",
            "# HELP jarvis_cache_size_bytes Current cache size in bytes",
            "# TYPE jarvis_cache_size_bytes gauge",
            f"jarvis_cache_size_bytes {cache['size_bytes']}",
            "# HELP jarvis_uptime_seconds Proxy uptime in seconds",
            "# TYPE jarvis_uptime_seconds gauge",
            f"jarvis_uptime_seconds {uptime:.1f}",
            "# HELP jarvis_websocket_connections_total WebSocket upgrades detected",
            "# TYPE jarvis_websocket_connections_total counter",
            f"jarvis_websocket_connections_total {s.websocket_connections}",
            "# HELP jarvis_websocket_frames_in_total WS frames received from clients",
            "# TYPE jarvis_websocket_frames_in_total counter",
            f"jarvis_websocket_frames_in_total {s.websocket_frames_in}",
            "# HELP jarvis_websocket_frames_out_total WS frames sent to clients",
            "# TYPE jarvis_websocket_frames_out_total counter",
            f"jarvis_websocket_frames_out_total {s.websocket_frames_out}",
        ]
        return "\n".join(lines) + "\n"

    # ── /api/v1/ REST endpoints ───────────────────────────────────────────────

    def _v1_status(self) -> dict:
        s = self.proxy.stats
        cache = self.proxy.cache.get_stats()
        return {
            "status": "ok",
            "total_requests": s.total_requests,
            "active_connections": s.active_connections,
            "threats_blocked": s.threats_blocked,
            "cache": cache,
            "uptime_seconds": round(time.time() - s.start_time, 1),
        }

    async def _flush_cache(self) -> None:
        async with self.proxy.cache.lock:
            self.proxy.cache.cache.clear()
        log.info("Cache flushed via management API")

    async def _handle_block_api(
        self,
        method: str,
        path: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if method == "POST":
            # Read JSON body
            try:
                body_raw = await asyncio.wait_for(reader.read(4096), timeout=5)
                data = json.loads(body_raw)
                domain = data.get("domain", "").strip()
                if domain:
                    self.proxy.add_blocked_domain(domain)
                    resp = json.dumps({"blocked": domain}).encode()
                    writer.write(
                        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(resp)}\r\n\r\n".encode() + resp
                    )
                else:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        elif method == "DELETE":
            domain = path.rstrip("/").split("/")[-1]
            self.proxy.remove_blocked_domain(domain)
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_har_export(self, writer: asyncio.StreamWriter) -> None:
        try:
            from har_export import export
            path = export(self.proxy)
            resp = json.dumps({"exported": path}).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(resp)}\r\n\r\n".encode() + resp
            )
        except Exception as exc:
            resp = json.dumps({"error": str(exc)}).encode()
            writer.write(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(resp)}\r\n\r\n".encode() + resp
            )
        await writer.drain()

    # ── Extended management REST API ──────────────────────────────────────────

    async def _serve_openapi_spec(self, writer: asyncio.StreamWriter) -> None:
        """Serve openapi.yaml from disk."""
        import os
        spec_path = os.path.join(os.path.dirname(__file__), "openapi.yaml")
        try:
            with open(spec_path, "rb") as f:
                body = f.read()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/yaml\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
        except FileNotFoundError:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    def _json_ok(self, data: object) -> bytes:
        body = json.dumps(data, separators=(",", ":")).encode()
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )

    def _json_created(self, data: object) -> bytes:
        body = json.dumps(data, separators=(",", ":")).encode()
        return (
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )

    async def _read_json(self, reader: asyncio.StreamReader) -> dict:
        raw = await asyncio.wait_for(reader.read(65536), timeout=5)
        return json.loads(raw)

    async def _handle_blocklist(
        self, method: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """GET /api/v1/blocklist — list all blocked domains.
        POST /api/v1/blocklist — add domain(s)  {"domains": ["example.com"]}"""
        if method == "GET":
            domains = sorted(self.proxy.filter_mgr._blocked_domains)
            writer.write(self._json_ok({"domains": domains, "count": len(domains)}))
        elif method == "POST":
            try:
                data = await self._read_json(reader)
                added = []
                for d in data.get("domains", [data.get("domain", "")]):
                    d = d.strip()
                    if d:
                        self.proxy.add_blocked_domain(d)
                        added.append(d)
                writer.write(self._json_created({"added": added}))
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_blocklist_item(
        self, method: str, domain: str, writer: asyncio.StreamWriter
    ) -> None:
        """DELETE /api/v1/blocklist/{domain}"""
        if method == "DELETE":
            self.proxy.remove_blocked_domain(domain)
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_allowlist(
        self, method: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """GET /api/v1/allowlist — list allowed/bypass domains.
        POST /api/v1/allowlist — add domain(s)  {"domains": ["safe.com"]}"""
        if method == "GET":
            domains = sorted(self.proxy.filter_mgr._allowed_domains)
            writer.write(self._json_ok({"domains": domains, "count": len(domains)}))
        elif method == "POST":
            try:
                data = await self._read_json(reader)
                added = []
                for d in data.get("domains", [data.get("domain", "")]):
                    d = d.strip().lower().lstrip("*.")
                    if d:
                        self.proxy.filter_mgr._allowed_domains.add(d)
                        added.append(d)
                writer.write(self._json_created({"added": added}))
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_allowlist_item(
        self, method: str, domain: str, writer: asyncio.StreamWriter
    ) -> None:
        """DELETE /api/v1/allowlist/{domain}"""
        if method == "DELETE":
            self.proxy.filter_mgr._allowed_domains.discard(domain.lower().lstrip("*."))
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_filters_config(
        self, method: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """GET /api/v1/filters — current filter settings.
        PATCH /api/v1/filters — update settings {"whitelist_mode": true}"""
        if method == "GET":
            writer.write(self._json_ok({
                "whitelist_mode": self.proxy.stats.whitelist_mode,
                "blocked_count":  len(self.proxy.filter_mgr._blocked_domains),
                "allowed_count":  len(self.proxy.filter_mgr._allowed_domains),
                "blocked_content_types": self.proxy._blocked_content_types,
            }))
        elif method in ("POST", "PATCH"):
            try:
                data = await self._read_json(reader)
                if "whitelist_mode" in data:
                    self.proxy.stats.whitelist_mode = bool(data["whitelist_mode"])
                if "blocked_content_types" in data:
                    self.proxy._blocked_content_types = [
                        t.lower() for t in data["blocked_content_types"]
                    ]
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_security_config(
        self, method: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """GET /api/v1/security — current security settings.
        PATCH /api/v1/security — update {"force_https": true}"""
        if method == "GET":
            import ipaddress as _ip
            writer.write(self._json_ok({
                "force_https":      self.proxy._force_https,
                "client_allowlist": [str(n) for n in self.proxy._client_allowlist],
                "client_denylist":  [str(n) for n in self.proxy._client_denylist],
                "anomaly_enabled":  self.proxy._anomaly_enabled,
                "anomaly_threshold_rps": (
                    self.proxy.anomaly_detector.threshold_rps
                    if self.proxy.anomaly_detector else None
                ),
            }))
        elif method in ("POST", "PATCH"):
            try:
                import ipaddress as _ip
                data = await self._read_json(reader)
                if "force_https" in data:
                    self.proxy._force_https = bool(data["force_https"])
                if "client_allowlist" in data:
                    self.proxy._client_allowlist = [
                        _ip.ip_network(c, strict=False)
                        for c in data["client_allowlist"]
                    ]
                if "client_denylist" in data:
                    self.proxy._client_denylist = [
                        _ip.ip_network(c, strict=False)
                        for c in data["client_denylist"]
                    ]
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    async def _handle_bandwidth_api(
        self, method: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """GET /api/v1/bandwidth — list bandwidth rules.
        POST /api/v1/bandwidth — add rule  {"cidr": "10.0.0.0/8", "bps": 5242880}
        DELETE /api/v1/bandwidth — remove rule {"cidr": "10.0.0.0/8"}"""
        if method == "GET":
            rules = [
                {"cidr": str(r.network), "bps": r.bps}
                for r in self.proxy.bw_policy._rules
            ]
            writer.write(self._json_ok({"rules": rules}))
        elif method == "POST":
            try:
                import ipaddress as _ip
                from bw_policy import BWRule
                data = await self._read_json(reader)
                cidr = data["cidr"]
                bps  = int(data.get("bps", 0))
                net  = _ip.ip_network(cidr, strict=False)
                # Prepend so new rules take priority
                self.proxy.bw_policy._rules.insert(0, BWRule(network=net, bps=bps))
                writer.write(self._json_created({"cidr": str(net), "bps": bps}))
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        elif method == "DELETE":
            try:
                import ipaddress as _ip
                data = await self._read_json(reader)
                cidr = data["cidr"]
                net  = _ip.ip_network(cidr, strict=False)
                self.proxy.bw_policy._rules = [
                    r for r in self.proxy.bw_policy._rules if r.network != net
                ]
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    # ── SSE ───────────────────────────────────────────────────────────────────

    async def _serve_sse(self, writer: asyncio.StreamWriter):
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            b"Cache-Control: no-cache\r\nConnection: keep-alive\r\n"
            b"Access-Control-Allow-Origin: *\r\n\r\n"
        )
        await writer.drain()
        q: asyncio.Queue = asyncio.Queue(maxsize=8)
        self._sse_queues.add(q)
        try:
            # send an immediate snapshot so the browser doesn't wait
            first = json.dumps(self._payload(), separators=(",", ":"))
            writer.write(f"data: {first}\n\n".encode())
            await writer.drain()
            while True:
                data = await q.get()
                writer.write(f"data: {data}\n\n".encode())
                await writer.drain()
        except Exception:
            pass
        finally:
            self._sse_queues.discard(q)
            try:
                writer.close()
            except Exception:
                pass

    # ── broadcast loop ────────────────────────────────────────────────────────

    async def _broadcast_loop(self):
        while True:
            await asyncio.sleep(0.25)
            if not self._sse_queues:
                continue
            try:
                payload = json.dumps(self._payload(), separators=(",", ":"))
            except Exception as exc:
                log.debug("Web UI payload error: %s", exc)
                continue
            for q in list(self._sse_queues):
                try:
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    q.put_nowait(payload)
                except Exception:
                    pass

    # ── payload serialiser ────────────────────────────────────────────────────

    def _payload(self) -> dict:
        s   = self.proxy.stats
        now = time.time()
        up  = max(now - s.start_time, 1)

        # rolling RPS
        delta = now - self._last_tick
        if delta >= 0.4:
            rps = (s.total_requests - self._last_count) / delta
            self._rps_history.append(round(rps, 2))
            self._last_count = s.total_requests
            self._last_tick  = now
        rps_cur = self._rps_history[-1] if self._rps_history else 0.0

        ct       = s.cache_hits + s.cache_misses
        hit_rate = s.cache_hits / ct * 100 if ct else 0
        avg_resp = sum(s.response_times) / len(s.response_times) if s.response_times else 0

        return {
            # top-level meta
            "uptime":           round(up, 1),
            "rps":              round(rps_cur, 2),
            "rps_history":      list(self._rps_history),
            "minute_history":   list(getattr(s, "minute_rps", deque())),
            "hour_history":     list(getattr(s, "hour_rps",   deque())),
            "cache_entries":    len(self.proxy.cache.cache),
            "ssl_inspection":   self.proxy.enable_ssl_inspection,
            "avg_resp":         round(avg_resp, 2),
            "hit_rate":         round(hit_rate, 1),
            # flat stats (mirrors TUI status bar exactly)
            "total_requests":       s.total_requests,
            "total_errors":         s.total_errors,
            "https_requests":       s.https_requests,
            "http_requests":        s.http_requests,
            "websocket_connections": s.websocket_connections,
            "websocket_frames_in":  s.websocket_frames_in,
            "websocket_frames_out": s.websocket_frames_out,
            "active_connections":   s.active_connections,
            "peak_connections":     s.peak_connections,
            "unique_clients":       len(s.unique_clients),
            "threats_blocked":      s.threats_blocked,
            "malicious_ips":        len(s.malicious_ips),
            "cache_hits":           s.cache_hits,
            "cache_misses":         s.cache_misses,
            "total_bytes_sent":     s.total_bytes_sent,
            "total_bytes_received": s.total_bytes_received,
            "current_upload_bps":   s.current_upload_bps,
            "current_download_bps": s.current_download_bps,
            "whitelist_mode":       s.whitelist_mode,
            # time-series arrays
            "upload_bps_history":   list(s.upload_bps_history),
            "download_bps_history": list(s.download_bps_history),
            "response_times":       list(s.response_times),
            "tcp_times":            list(s.tcp_times),
            "dns_times":            list(s.dns_times),
            "ssl_times":            list(s.ssl_times),
            # tables
            "status_codes":  {str(k): v for k, v in s.status_codes.items()},
            "domain_stats": {
                d: {
                    "requests": ds["requests"],
                    "errors":   ds["errors"],
                    "bytes":    ds["bytes"],
                    "avg_time": round(ds["avg_time"], 2),
                    "methods":  dict(ds["methods"].most_common(3)),
                }
                for d, ds in sorted(
                    s.domain_stats.items(),
                    key=lambda x: x[1]["requests"], reverse=True
                )[:50]
            },
            "methods":       dict(s.methods.most_common()),
            "content_types": {ct.value: c for ct, c in s.content_types.most_common()},
            "geo_stats":     dict(sorted(s.geo_stats.items(), key=lambda x: x[1], reverse=True)[:30]),
            "client_requests": dict(
                sorted(s.client_requests.items(), key=lambda x: x[1], reverse=True)[:20]
            ),
            "blocked_domains": sorted(s.blocked_domains),
            "allowed_domains": sorted(s.allowed_domains),
            # security threats (newest first)
            "security_threats": [
                {
                    "level":     t.level.value,
                    "reason":    t.reason,
                    "timestamp": t.timestamp,
                    "ip":        t.ip,
                    "host":      t.host,
                    "patterns":  t.patterns[:2],
                }
                for t in list(s.security_threats)[-40:][::-1]
            ],
            # recent traffic (newest first, 50 rows)
            "recent_requests": [
                {
                    "ts":              r.timestamp[11:19] if len(r.timestamp) > 10 else r.timestamp,
                    "timestamp":       r.timestamp,
                    "is_https":        r.is_https,
                    "method":          r.method or "CONN",
                    "client_ip":       r.client_ip or "-",
                    "host":            r.host or "-",
                    "port":            r.port,
                    "status_code":     r.status_code,
                    "body_bytes":      r.body_bytes or 0,
                    "response_time_ms":r.response_time_ms,
                    "tcp_connect_ms":  r.tcp_connect_ms,
                    "security_level":  r.security_level.value,
                    "user_agent":      r.user_agent or "",
                    "url":             r.url or "-",
                    "error":           r.error,
                    "cached":          r.cached,
                    "compressed":      r.compressed,
                    "dns": {
                        "dns_time_ms": r.dns.dns_time_ms,
                        "cached":      r.dns.cached,
                        "is_ipv6":     r.dns.is_ipv6,
                        "addresses":   r.dns.addresses[:3],
                    } if r.dns else {},
                    "geo_location": {
                        "country": r.geo_location.country,
                        "city":    r.geo_location.city,
                        "isp":     r.geo_location.isp,
                        "is_vpn":  r.geo_location.is_vpn,
                    } if r.geo_location else None,
                    "ssl_info": {
                        "protocol": r.ssl_info.protocol,
                        "cipher":   r.ssl_info.cipher,
                    } if r.ssl_info else None,
                    "request_headers":  dict(list(r.request_headers.items())[:8]),
                    "response_headers": dict(list(r.response_headers.items())[:8]),
                }
                for r in list(s.recent_requests)[-50:][::-1]
            ],
            # live log
            "log_lines": list(s.log_lines)[-150:],
            "log_total": s.log_total,
            # alerts
            "alerts": list(getattr(self.proxy, "alerts", [])),
        }
