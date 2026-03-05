"""Header rewrite rules for J.A.R.V.I.S. Proxy.

Config-driven add / remove / replace of request and response headers.

Config section (config.yaml)::

    rewrite:
      request:
        - {header: "X-Via", value: "JARVIS", action: set}
        - {header: "X-Forwarded-For", action: remove}
      response:
        - {header: "Server", action: remove}
        - {header: "X-Powered-By", action: remove}
"""
from __future__ import annotations

from dataclasses import dataclass
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


class HeaderRewriter:
    """Applies a list of RewriteRules to request or response headers."""

    def __init__(
        self,
        request_rules: List[dict] = (),
        response_rules: List[dict] = (),
    ):
        self._req_rules: List[RewriteRule] = [self._parse(r) for r in request_rules]
        self._resp_rules: List[RewriteRule] = [self._parse(r) for r in response_rules]

    @staticmethod
    def _parse(rule: dict) -> RewriteRule:
        return RewriteRule(
            header=rule.get("header", ""),
            action=rule.get("action", "set"),
            value=rule.get("value"),
            match=rule.get("match"),
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

    @classmethod
    def from_config(cls, config: dict) -> "HeaderRewriter":
        """Build from the 'rewrite' section of config.yaml."""
        rewrite = config.get("rewrite", {})
        return cls(
            request_rules=rewrite.get("request", []),
            response_rules=rewrite.get("response", []),
        )
