"""Download the MaxMind GeoLite2-City database at build time."""
from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path

EDITION = "GeoLite2-City"
URL = "https://download.maxmind.com/app/geoip_download"
#: Beside the database file, so MAILTRACE_MAXMIND_DB can point straight at it.
DESTINATION = Path(__file__).resolve().parent.parent / "data" / f"{EDITION}.mmdb"
TIMEOUT_SECONDS = 120


def fetch(key: str, destination: Path = DESTINATION) -> Path | None:
    """Download and unpack the database; None when it could not be fetched."""
    import httpx

    params = {"edition_id": EDITION, "license_key": key, "suffix": "tar.gz"}
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = client.get(URL, params=params)
    except httpx.HTTPError as exc:
        print(f"GeoLite2 download failed ({type(exc).__name__}: {exc}); using ip-api.com", file=sys.stderr)
        return None
    if response.status_code == 401:
        print("GeoLite2 rejected MAXMIND_LICENSE_KEY; using ip-api.com", file=sys.stderr)
        return None
    if response.status_code != 200:
        print(f"GeoLite2 download returned HTTP {response.status_code}; using ip-api.com", file=sys.stderr)
        return None

    # The archive is a single dated directory holding the .mmdb and its licence.
    try:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
            member = next((m for m in archive.getmembers() if m.name.endswith(".mmdb")), None)
            if member is None:
                print("GeoLite2 archive contained no .mmdb; using ip-api.com", file=sys.stderr)
                return None
            extracted = archive.extractfile(member)
            if extracted is None:
                print("GeoLite2 archive member could not be read; using ip-api.com", file=sys.stderr)
                return None
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(extracted.read())
    except (tarfile.TarError, OSError) as exc:
        print(f"GeoLite2 archive could not be unpacked ({type(exc).__name__}: {exc}); using ip-api.com", file=sys.stderr)
        return None
    return destination


def main() -> int:
    key = (os.environ.get("MAXMIND_LICENSE_KEY") or "").strip()
    if not key:
        print("MAXMIND_LICENSE_KEY is not set; geolocation will use ip-api.com")
        return 0
    path = fetch(key)
    if path is None:
        return 0
    size_mb = path.stat().st_size / 1e6
    print(f"GeoLite2-City ready at {path} ({size_mb:.0f} MB)")
    print(f"Set MAILTRACE_MAXMIND_DB={path} for the service to prefer it over ip-api.com")
    return 0


if __name__ == "__main__":
    sys.exit(main())
