"""proxy.cache — re-exports AdvancedCache and adds the test-friendly _parse_max_age helper."""
from cache import AdvancedCache  # re-export the production cache


def _parse_max_age(cc_header: str, default_ttl: float) -> float:
    """Parse the effective max-age from a Cache-Control header value.

    s-maxage takes precedence over max-age (RFC 7234 §5.2.2.9).
    Negative values are clamped to 0.
    Returns *default_ttl* if neither directive is present.
    """
    s_maxage: float | None = None
    max_age: float | None = None

    for directive in cc_header.lower().split(","):
        directive = directive.strip()
        if directive.startswith("s-maxage="):
            try:
                s_maxage = max(0.0, float(directive[9:]))
            except ValueError:
                pass
        elif directive.startswith("max-age="):
            try:
                max_age = max(0.0, float(directive[8:]))
            except ValueError:
                pass

    if s_maxage is not None:
        return s_maxage
    if max_age is not None:
        return max_age
    return float(default_ttl)


__all__ = ["AdvancedCache", "_parse_max_age"]
