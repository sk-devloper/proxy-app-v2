# J.A.R.V.I.S. Proxy

A production-grade async HTTPS proxy with SSL/TLS inspection, request filtering, security analysis, RFC-7234 caching, a live Textual TUI, and a web dashboard.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`

### Optional dependencies

| Feature | Package | Command |
|---------|---------|---------|
| SSL/TLS MITM | `cryptography` | `pip install cryptography` |
| GeoIP lookups (via ip-api.com) | `aiohttp` | `pip install aiohttp` |
| Textual TUI | `textual` | `pip install textual` |

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the proxy (reads config.yaml)
python main.py
```

The proxy listens on port **8888** and the web dashboard on port **8890** by default.

## Docker

```bash
# Build and run with docker-compose
docker-compose up

# Run headless (no TUI) — default in Docker
docker run jarvis-proxy

# Run with the Textual TUI
docker run -it jarvis-proxy
```

The compose file maps ports `8888` (proxy) and `8890` (web UI), and mounts `./logs`, `./certs`, and `./config.yaml`.

## Configuration

All settings live in **`config.yaml`**. Edit the file and restart to apply changes.

```yaml
proxy:
  host: "0.0.0.0"
  port: 8888
  ssl_inspection: true
  max_connections: 5000
  connect_timeout: 90.0
  read_timeout: 100.0
  body_timeout: 600.0

cache:
  max_size: 10000
  ttl: 36000            # seconds

geoip:
  provider: "ip-api"    # "ip-api" (free, no key) or "mock"
  rate_limit: 45        # requests/min (ip-api.com free tier limit)

security:
  rate_limit_window: 6000
  rate_limit_max: 100000

database:
  path: "logs/jarvis.db"

web_ui:
  port: 8890

filter:
  blocklist_file: "filters/blocklist.txt"
  allowlist_file: "filters/allowlist.txt"
  reload_interval: 60   # seconds between hot-reloads
  whitelist_mode: false
  bypass_domains: []

logging:
  level: "DEBUG"
  max_bytes: 10485760   # 10 MB per file before rotation
  backup_count: 5
  files:
    main:        "logs/jarvis.log"
    access:      "logs/access.log"
    error:       "logs/error.log"
    security:    "logs/security.log"
    performance: "logs/performance.log"
```

## Web dashboard

A built-in HTTP dashboard streams live stats via Server-Sent Events. Open it from any device on the LAN:

```
http://<host>:8890
```

Tabs: **Dashboard · Traffic · Security · Domains · Performance · Geo · Log · History**

## SSL/TLS MITM inspection

Enable in `config.yaml`:

```yaml
proxy:
  ssl_inspection: true
```

Requires `cryptography`:

```bash
pip install cryptography
```

On first run a CA certificate is generated at `certs/ca.crt`. Import it into your browser/OS trust store to avoid certificate warnings.

## GeoIP lookups

GeoIP resolution uses [ip-api.com](https://ip-api.com) — no API key or database download required. Install `aiohttp` to enable network lookups:

```bash
pip install aiohttp
```

Private, loopback, and link-local IPs are resolved locally without a network call. The free ip-api.com tier allows 45 requests/minute (configurable via `geoip.rate_limit`).

## Filtering

Edit `filters/blocklist.txt` and `filters/allowlist.txt` to control which domains are blocked or allowed. Changes are hot-reloaded every `filter.reload_interval` seconds (default 60 s) — no restart needed.

**File format:**

```
# Comment lines start with #
example.com          # blocks example.com and *.example.com
*.ads.com            # leading *. is stripped — same as ads.com
regex:.*\.ad\..*     # full-URL regex match (prefix with "regex:")
```

Enable whitelist mode (only allowlisted domains pass) in `config.yaml`:

```yaml
filter:
  whitelist_mode: true
```

## Security analysis

The `SecurityAnalyzer` inspects every request for:

- Known malicious domains
- Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`)
- Malicious URL patterns (XSS, SQLi, path traversal, etc.)
- Unusually long URLs (> 2 000 characters)
- Per-IP rate limiting

Threats are classified as `SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `BLOCKED` and logged to `logs/security.log` and `logs/jarvis.db`.

## Caching

Responses are cached using an LRU + TTL strategy with RFC-7234-aware cacheability checks (`Cache-Control`, `Expires`, `ETag`, `Last-Modified`). Hop-by-hop headers are never stored. Configure size and TTL in `config.yaml` under the `cache` section.

## Logs and data

| Path | Contents |
|------|----------|
| `logs/jarvis.log` | Main structured log |
| `logs/access.log` | Per-request access log |
| `logs/error.log` | Error log |
| `logs/security.log` | Threat / security events |
| `logs/performance.log` | Latency and performance metrics |
| `logs/jarvis.db` | SQLite request + threat log |
| `certs/` | CA + per-host certificates (SSL MITM) |

Log files rotate at 10 MB and keep 5 backups (configurable).

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

Test modules: `test_auth`, `test_cache`, `test_config`, `test_filter`, `test_security`.
