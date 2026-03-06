"""Header and body rewrite rules for J.A.R.V.I.S. Proxy.

Config-driven add / remove / replace of request and response headers,
plus regex find/replace on response bodies.

Config section (config.yaml)::

    rewrite:
      request:
        - {header: "X-Via", value: "JARVIS", action: set}
        - {header: "X-Forwarded-For", action: remove}
      response:
        - {header: "Server", action: remove}
        - {header: "X-Powered-By", action: remove}
      body:
        - {pattern: "foo", replacement: "bar"}
        - {pattern: "(?i)old company name", replacement: "ACME", content_types: ["text/html", "text/plain"]}
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional


@dataclass
class RewriteRule:
    """A single header rewrite rule."""
    header: str                          # header name (case-insensitive)
    action: Literal["set", "remove", "replace"] = "set"
    value: Optional[str] = None          # required for set / replace
    match: Optional[str] = None          # for replace: substring to match in existing value

    def apply(self, headers: Dict[str, str]) -> Dict[str, str]:
        result = dict(headers)
        key_lower = self.header.lower()
        existing_key = next((k for k in result if k.lower() == key_lower), None)

        if self.action == "remove":
            if existing_key:
                del result[existing_key]
        elif self.action == "set":
            # Remove old value regardless of original casing
            if existing_key:
                del result[existing_key]
            result[self.header] = self.value or ""
        elif self.action == "replace":
            if existing_key and self.match and self.value is not None:
                result[existing_key] = result[existing_key].replace(self.match, self.value)
        return result


@dataclass
class BodyRewriteRule:
    """A single response body rewrite rule (regex find/replace)."""
    pattern: str
    replacement: str
    # Optional list of Content-Type substrings this rule applies to.
    # Empty list means apply to all text/* types.
    content_types: List[str] = field(default_factory=list)
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern)

    def applies_to(self, content_type: str) -> bool:
        ct = content_type.lower()
        if self.content_types:
            return any(t.lower() in ct for t in self.content_types)
        # Default: apply to text/* content only
        return ct.startswith("text/") or "html" in ct or "json" in ct or "xml" in ct

    def apply(self, body: bytes, content_type: str) -> bytes:
        if not self.applies_to(content_type):
            return body
        try:
            text = body.decode("utf-8", errors="replace")
            text = self._compiled.sub(self.replacement, text)
            return text.encode("utf-8")
        except Exception:
            return body


class HeaderRewriter:
    """Applies a list of RewriteRules to request or response headers."""

    def __init__(
        self,
        request_rules: List[dict] = (),
        response_rules: List[dict] = (),
        body_rules: List[dict] = (),
    ):
        self._req_rules: List[RewriteRule] = [self._parse(r) for r in request_rules]
        self._resp_rules: List[RewriteRule] = [self._parse(r) for r in response_rules]
        self._body_rules: List[BodyRewriteRule] = [self._parse_body(r) for r in body_rules]

    @staticmethod
    def _parse(rule: dict) -> RewriteRule:
        return RewriteRule(
            header=rule.get("header", ""),
            action=rule.get("action", "set"),
            value=rule.get("value"),
            match=rule.get("match"),
        )

    @staticmethod
    def _parse_body(rule: dict) -> BodyRewriteRule:
        return BodyRewriteRule(
            pattern=rule.get("pattern", ""),
            replacement=rule.get("replacement", ""),
            content_types=rule.get("content_types", []),
        )

    def apply_request(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a new headers dict with request rules applied."""
        for rule in self._req_rules:
            headers = rule.apply(headers)
        return headers

    def apply_response(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a new headers dict with response rules applied."""
        for rule in self._resp_rules:
            headers = rule.apply(headers)
        return headers

    def apply_body(self, body: bytes, content_type: str) -> bytes:
        """Apply body rewrite rules and return modified body bytes."""
        for rule in self._body_rules:
            body = rule.apply(body, content_type)
        return body

    @property
    def has_body_rules(self) -> bool:
        return bool(self._body_rules)

    @classmethod
    def from_config(cls, config: dict) -> "HeaderRewriter":
        """Build from the 'rewrite' section of config.yaml."""
        rewrite = config.get("rewrite", {})
        return cls(
            request_rules=rewrite.get("request", []),
            response_rules=rewrite.get("response", []),
            body_rules=rewrite.get("body", []),
        )
