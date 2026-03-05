import re
import time
from typing import Dict, List, Tuple
from collections import defaultdict, deque

from models import SecurityLevel, ContentType
from config import get as cfg_get


class SecurityAnalyzer:
    """Advanced security analysis and threat detection"""

    def __init__(self):
        # Precompiled for zero per-request compilation overhead
        self._malicious_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'onerror\s*=',
                r'onclick\s*=',
                r'\.\./\.\.',
                r'union\s+select',
                r'drop\s+table',
                r'exec\s*\(',
                r'eval\s*\(',
            ]
        ]

        self.malicious_domains = {
            'malware.com', 'phishing.net', 'scam.org'
        }

        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq'}

        self.rate_limits: Dict[str, deque] = defaultdict(deque)
        self.rate_limit_window = cfg_get("security", "rate_limit_window", 6000)
        self.rate_limit_max    = cfg_get("security", "rate_limit_max",    100000)

    def analyze_url(self, url: str, host: str) -> Tuple[SecurityLevel, str]:
        """Analyze URL for threats"""
        if any(bad in host for bad in self.malicious_domains):
            return SecurityLevel.MALICIOUS, "Known malicious domain"

        if any(host.endswith(tld) for tld in self.suspicious_tlds):
            return SecurityLevel.SUSPICIOUS, "Suspicious TLD"

        for pat in self._malicious_patterns:
            if pat.search(url):
                return SecurityLevel.SUSPICIOUS, f"Suspicious pattern: {pat.pattern}"

        if len(url) > 2000:
            return SecurityLevel.SUSPICIOUS, "Unusually long URL"

        return SecurityLevel.SAFE, "OK"

    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client exceeds rate limit"""
        now = time.time()
        window = self.rate_limits[client_ip]

        # Drop expired entries from the front in O(1) amortised
        cutoff = now - self.rate_limit_window
        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= self.rate_limit_max:
            return False

        window.append(now)
        return True

    def analyze_headers(self, headers: Dict[str, str]) -> Tuple[SecurityLevel, str]:
        """Analyze request headers for threats"""
        user_agent = headers.get('user-agent', '').lower()

        attack_tools = ['sqlmap', 'nmap', 'nikto', 'nessus', 'masscan']
        if any(tool in user_agent for tool in attack_tools):
            return SecurityLevel.MALICIOUS, f"Attack tool detected in User-Agent"

        # Don't flag missing UA — mobile apps / CONNECT tunnels legitimately omit it
        return SecurityLevel.SAFE, "OK"


class TrafficInspector:
    """Deep packet inspection and analysis"""

    def __init__(self):
        self.patterns = {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\./\.\./",
                r"%2e%2e/",
            ]
        }

    def inspect_content(self, content: bytes, content_type: str) -> List[str]:
        """Inspect content for threats"""
        threats = []

        try:
            text = content.decode('utf-8', errors='ignore')[:10000]

            for threat_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        threats.append(f"{threat_type}: {pattern}")
        except Exception:
            pass

        return threats

    def analyze_response(self, status_code: int, headers: Dict[str, str],
                         body: bytes) -> dict:
        """Analyze HTTP response"""
        info = {
            'compressed': False,
            'content_type': ContentType.OTHER,
            'size': len(body),
            'has_security_headers': False,
            'threats': []
        }

        encoding = headers.get('content-encoding', '').lower()
        info['compressed'] = encoding in ['gzip', 'deflate', 'br']

        content_type = headers.get('content-type', '').lower()
        if 'html' in content_type:
            info['content_type'] = ContentType.HTML
        elif 'json' in content_type:
            info['content_type'] = ContentType.JSON
        elif 'image' in content_type:
            info['content_type'] = ContentType.IMAGE
        elif 'video' in content_type:
            info['content_type'] = ContentType.VIDEO
        elif 'javascript' in content_type:
            info['content_type'] = ContentType.SCRIPT
        elif 'css' in content_type:
            info['content_type'] = ContentType.STYLE

        security_headers = [
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'content-security-policy'
        ]
        info['has_security_headers'] = any(h in headers for h in security_headers)

        info['threats'] = self.inspect_content(body, content_type)

        return info
