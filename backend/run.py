"""
Entry point: ``python run.py`` starts the MailTrace web server with the
settings read from the environment / ``.env`` (see ``app/config.py``).

Set ``MAILTRACE_HOST=0.0.0.0`` to let phones and laptops on the same Wi-Fi
open the dashboard; the addresses they should use are printed at startup.
"""
from __future__ import annotations

import logging
import socket

import uvicorn

from app.config import settings
from app.schemas import ENGINE_VERSION


def lan_addresses() -> list[str]:
    """This machine's addresses on the local network, best effort."""
    found: list[str] = []
    # The UDP "connect" needs no traffic; it just picks the outbound interface.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        found.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except OSError:
        pass
    return [ip for i, ip in enumerate(found) if ip not in found[:i] and not ip.startswith(("127.", "169.254."))]


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    print(f"MailTrace {ENGINE_VERSION}  (press Ctrl+C to stop)")
    if settings.host in ("0.0.0.0", "::"):
        print(f"  On this computer : http://127.0.0.1:{settings.port}")
        for ip in lan_addresses():
            print(f"  On the same Wi-Fi: http://{ip}:{settings.port}   <- use this one for the QR code")
        print("  Note: anyone on this network can open it while the server runs.")
    else:
        print(f"  http://{settings.host}:{settings.port}")
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
