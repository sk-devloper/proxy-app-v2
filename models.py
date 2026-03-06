import time
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque, defaultdict, Counter
from enum import Enum

# Configuration
BUFFER_SIZE = 131072  # 128KB
DEFAULT_TIMEOUT = 30.0
MAX_HEADER_SIZE = 131072
MAX_HISTORY = 5000
STATS_UPDATE_INTERVAL = 0.05
CACHE_MAX_SIZE = 1000
CACHE_TTL = 3600
GEO_CACHE_SIZE = 10000


# ── picklable factory functions (lambdas can't be pickled) ───────────────────

def _domain_stat_factory():
    return {
        'requests': 0,
        'errors': 0,
        'bytes': 0,
        'avg_time': 0.0,
        'status_codes': Counter(),
        'methods': Counter(),
        'last_seen': None,
    }

def _domain_stats_default():  return defaultdict(_domain_stat_factory)
def _int_defaultdict():       return defaultdict(int)
def _deque100():              return deque(maxlen=100)
def _deque1000():             return deque(maxlen=1000)
def _deque5000():             return deque(maxlen=MAX_HISTORY)
def _deque60():               return deque(maxlen=60)
def _deque24():               return deque(maxlen=24)


class SecurityLevel(Enum):
    """Security threat levels"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"


class ContentType(Enum):
    """Content type categories"""
    HTML = "html"
    JSON = "json"
    IMAGE = "image"
    VIDEO = "video"
    SCRIPT = "script"
    STYLE = "style"
    FONT = "font"
    OTHER = "other"


@dataclass
class GeoLocation:
    """Geolocation information"""
    ip: str
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    is_vpn: bool = False
    is_tor: bool = False
    latitude: float = 0.0
    longitude: float = 0.0


@dataclass
class SecurityThreat:
    """Security threat information"""
    level: SecurityLevel
    reason: str
    timestamp: str
    ip: str
    host: str
    patterns: List[str] = field(default_factory=list)


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    timestamp: float
    size: int
    hit_count: int = 0
    last_access: float = field(default_factory=time.time)
    ttl: float = 3600.0  # per-entry TTL derived from server Cache-Control max-age


@dataclass
class DNSInfo:
    addresses: List[str]
    dns_time_ms: float
    is_ipv6: bool = False
    cached: bool = False


@dataclass
class SSLInfo:
    """SSL/TLS certificate information"""
    issuer: str = ""
    subject: str = ""
    version: str = ""
    valid_from: str = ""
    valid_until: str = ""
    fingerprint: str = ""
    cipher: str = ""
    protocol: str = ""


@dataclass
class ConnectionMetrics:
    type: str
    host: str
    port: int
    dns: DNSInfo
    tcp_connect_ms: float
    timestamp: str
    method: Optional[str] = None
    url: Optional[str] = None
    response_time_ms: Optional[float] = None
    body_bytes: Optional[int] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[ContentType] = None
    cached: bool = False
    compressed: bool = False
    security_level: SecurityLevel = SecurityLevel.SAFE
    geo_location: Optional[GeoLocation] = None
    ssl_info: Optional[SSLInfo] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    is_https: bool = False
    request_id: Optional[str] = None


@dataclass
class ProxyStats:
    """Real-time proxy statistics"""
    total_requests: int = 0
    total_errors: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    active_connections: int = 0
    requests_per_second: float = 0.0
    avg_response_time: float = 0.0
    start_time: float = field(default_factory=time.time)
    peak_connections: int = 0
    https_requests: int = 0
    http_requests: int = 0
    websocket_connections: int = 0   # cumulative WS upgrades detected
    websocket_frames_in: int = 0     # frames received from clients
    websocket_frames_out: int = 0    # frames sent to clients

    # Cache stats
    cache_hits: int = 0
    cache_misses: int = 0
    cache_size_bytes: int = 0

    # Security stats
    threats_blocked: int = 0
    malicious_ips: Set[str] = field(default_factory=set)

    # Per-domain stats
    domain_stats: Dict[str, Dict[str, Any]] = field(default_factory=_domain_stats_default)

    # Status code distribution
    status_codes: Dict[int, int] = field(default_factory=_int_defaultdict)

    # Method distribution
    methods: Counter = field(default_factory=Counter)

    # Content type distribution
    content_types: Counter = field(default_factory=Counter)

    # Recent requests
    recent_requests: deque = field(default_factory=_deque5000)

    # Blocked domains
    blocked_domains: Set[str] = field(default_factory=set)

    # Allowed domains (whitelist mode)
    allowed_domains: Set[str] = field(default_factory=set)
    whitelist_mode: bool = False

    # Performance metrics
    dns_times: deque = field(default_factory=_deque100)
    tcp_times: deque = field(default_factory=_deque100)
    response_times: deque = field(default_factory=_deque100)
    ssl_times: deque = field(default_factory=_deque100)

    # Security threats
    security_threats: deque = field(default_factory=_deque1000)

    # Client tracking
    unique_clients: Set[str] = field(default_factory=set)
    client_requests: Dict[str, int] = field(default_factory=_int_defaultdict)

    # Geographic data
    geo_stats: Dict[str, int] = field(default_factory=_int_defaultdict)

    # Bandwidth by hour
    hourly_bandwidth: Dict[int, int] = field(default_factory=_int_defaultdict)

    # Live bandwidth (updated every second by bandwidth_tracker_task)
    current_upload_bps:   float = 0.0
    current_download_bps: float = 0.0
    upload_bps_history:   deque = field(default_factory=_deque60)
    download_bps_history: deque = field(default_factory=_deque60)

    # Historical sampling — persisted with save_stats
    minute_rps: deque = field(default_factory=_deque60)   # req/min, last 60 mins
    hour_rps:   deque = field(default_factory=_deque24)   # req/hr,  last 24 hrs

    # Live log lines for the Log pane  [(timestamp_str, security_color, message), ...]
    log_lines: list = field(default_factory=list)
    log_total: int  = 0   # monotonically increasing — used as a read cursor by LogPane
