"""Plugin system for J.A.R.V.I.S. Proxy.

Allows loading custom Python modules as request/response middleware handlers.
Each plugin file may define any combination of:

    async def on_request(method, url, headers) -> dict | None
        Called before the request is forwarded upstream.
        Return a dict with keys 'method', 'url', 'headers' to override them,
        or None / omit return to pass through unchanged.

    async def on_response(status_code, headers, body_sample) -> dict | None
        Called after the response headers (and up to 32 KB of body) are read.
        Return a dict with keys 'status_code', 'headers' to override them,
        or None / omit return to pass through unchanged.

    def on_load(config: dict) -> None
        Called once when the plugin is loaded, with the full proxy config dict.

Config section (config.yaml)::

    plugins:
      - path/to/my_plugin.py
      - /absolute/path/to/another_plugin.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("JARVIS.plugins")


class PluginManager:
    """Loads and dispatches to user-supplied plugin modules."""

    def __init__(self) -> None:
        self._on_request_hooks:  List[Callable] = []
        self._on_response_hooks: List[Callable] = []

    def load_plugin(self, path: str, config: dict) -> None:
        """Load a plugin from *path* and register its hooks."""
        p = Path(path)
        if not p.exists():
            log.warning("Plugin not found: %s", path)
            return

        spec = importlib.util.spec_from_file_location(f"jarvis_plugin_{p.stem}", p)
        if spec is None or spec.loader is None:
            log.warning("Could not load plugin spec: %s", path)
            return

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[attr-defined]
        except Exception as exc:
            log.error("Error executing plugin %s: %s", path, exc)
            return

        # Register hooks
        if hasattr(module, "on_request"):
            self._on_request_hooks.append(module.on_request)
            log.info("Plugin %s: registered on_request hook", p.name)

        if hasattr(module, "on_response"):
            self._on_response_hooks.append(module.on_response)
            log.info("Plugin %s: registered on_response hook", p.name)

        # One-time init callback
        if hasattr(module, "on_load"):
            try:
                module.on_load(config)
            except Exception as exc:
                log.error("Plugin %s on_load error: %s", path, exc)

        log.info("Loaded plugin: %s", path)

    async def run_request_hooks(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        """Run all on_request hooks and return (possibly modified) request attrs."""
        result: Dict[str, Any] = {"method": method, "url": url, "headers": headers}
        for hook in self._on_request_hooks:
            try:
                override = await hook(result["method"], result["url"], result["headers"])
                if override and isinstance(override, dict):
                    result.update(override)
            except Exception as exc:
                log.error("on_request hook error: %s", exc)
        return result

    async def run_response_hooks(
        self,
        status_code: int,
        headers: Dict[str, str],
        body_sample: bytes,
    ) -> Dict[str, Any]:
        """Run all on_response hooks and return (possibly modified) response attrs."""
        result: Dict[str, Any] = {
            "status_code": status_code,
            "headers": headers,
            "body_sample": body_sample,
        }
        for hook in self._on_response_hooks:
            try:
                override = await hook(
                    result["status_code"], result["headers"], result["body_sample"]
                )
                if override and isinstance(override, dict):
                    result.update(override)
            except Exception as exc:
                log.error("on_response hook error: %s", exc)
        return result

    @property
    def has_request_hooks(self) -> bool:
        return bool(self._on_request_hooks)

    @property
    def has_response_hooks(self) -> bool:
        return bool(self._on_response_hooks)

    @classmethod
    def from_config(cls, config: dict) -> "PluginManager":
        """Build and load all plugins listed in config."""
        mgr = cls()
        for plugin_path in config.get("plugins", []):
            mgr.load_plugin(plugin_path, config)
        return mgr
