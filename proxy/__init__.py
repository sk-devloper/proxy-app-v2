"""J.A.R.V.I.S. Proxy — Python package root.

Exposes the enterprise API used by tests and the management layer.
The async runtime lives in the flat modules at the package root.
"""
import importlib.util
import os as _os

from proxy.config import ProxyConfig

# Load proxy.py (the async runtime) which is shadowed by this package directory.
# Falls back to the Cython-compiled .so when the source file is not present.
_runtime_path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "proxy.py")
if not _os.path.exists(_runtime_path):
    import glob as _glob
    _so_candidates = _glob.glob(
        _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "proxy.cpython-*.so")
    )
    if _so_candidates:
        _runtime_path = _so_candidates[0]
_spec = importlib.util.spec_from_file_location("_proxy_runtime", _runtime_path)
_runtime = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_runtime)

JARVISProxy = _runtime.JARVISProxy

__all__ = ["ProxyConfig", "JARVISProxy"]
