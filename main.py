import asyncio

from rich.console import Console

import config as cfg
from proxy import JARVISProxy

console = Console()


async def main():
    """Main entry point"""
    proxy = JARVISProxy(
        host=cfg.get("proxy", "host", "0.0.0.0"),
        port=cfg.get("proxy", "port", 8888),
        enable_ssl_inspection=cfg.get("proxy", "ssl_inspection", False),
    )

    try:
        await proxy.start()
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[bold yellow]⚡ Shutting down J.A.R.V.I.S. HTTPS Proxy...[/bold yellow]")
    finally:
        console.print("[bold green]✨ J.A.R.V.I.S. terminated gracefully[/bold green]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
