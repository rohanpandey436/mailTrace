"""
Build the dashboard stylesheet with Tailwind CSS.

The frontend has no Node or bundler, so this uses Tailwind's standalone CLI: a
single binary downloaded on demand into a cache directory outside the
repository.  Its output, css/app.css, is committed so every deployment serves
the dashboard without a toolchain.

    python frontend/build_css.py            # build css/app.css
    python frontend/build_css.py --check    # fail if the committed CSS is stale

CI runs ``--check`` so the committed file cannot drift from its source.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "css" / "tailwind.css"
OUTPUT = HERE / "css" / "app.css"

#: Pinned so every machine and CI produce identical bytes.
TAILWIND_VERSION = "v4.3.3"
RELEASE = f"https://github.com/tailwindlabs/tailwindcss/releases/download/{TAILWIND_VERSION}"

#: Outside the repository; shared between checkouts.
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "mailtrace-tailwind"


def asset_name() -> str:
    """The release asset for this machine."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arm = machine in {"arm64", "aarch64"}
    if system == "windows":
        return "tailwindcss-windows-x64.exe"
    if system == "darwin":
        return "tailwindcss-macos-arm64" if arm else "tailwindcss-macos-x64"
    if system == "linux":
        return "tailwindcss-linux-arm64" if arm else "tailwindcss-linux-x64"
    raise SystemExit(f"no Tailwind standalone build for {system}/{machine}")


def cli() -> Path:
    """Path to the Tailwind CLI, downloading it the first time."""
    name = asset_name()
    binary = CACHE / f"{TAILWIND_VERSION}-{name}"
    if binary.is_file() and binary.stat().st_size > 0:
        return binary

    url = f"{RELEASE}/{name}"
    print(f"downloading Tailwind {TAILWIND_VERSION} ({name})…")
    CACHE.mkdir(parents=True, exist_ok=True)
    # Temporary name first, so an interrupted download is never mistaken for a cached binary.
    partial = binary.with_suffix(binary.suffix + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=300) as response, partial.open("wb") as handle:
            while chunk := response.read(1 << 20):
                handle.write(chunk)
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise SystemExit(f"could not download {url}: {exc}") from exc
    partial.replace(binary)
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"cached at {binary}")
    return binary


def build(destination: Path) -> None:
    """Run Tailwind over tailwind.css, writing ``destination``."""
    command = [
        str(cli()),
        "--input", str(SOURCE),
        "--output", str(destination),
        "--minify",
    ]
    # The @source globs in tailwind.css resolve relative to the frontend directory.
    result = subprocess.run(command, cwd=HERE, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"tailwindcss exited {result.returncode}")
    # Tailwind reports its timing on stderr even when it succeeds.
    sys.stderr.write(result.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="build to a temporary file and fail if it differs from the committed CSS",
    )
    args = parser.parse_args()

    if not args.check:
        build(OUTPUT)
        size_kb = OUTPUT.stat().st_size / 1024
        print(f"{OUTPUT.relative_to(HERE.parent)} written ({size_kb:.1f} KB)")
        return 0

    if not OUTPUT.is_file():
        print(f"{OUTPUT} does not exist; run: python frontend/build_css.py", file=sys.stderr)
        return 1
    fresh = OUTPUT.with_suffix(".check.css")
    try:
        build(fresh)
        committed = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
        rebuilt = hashlib.sha256(fresh.read_bytes()).hexdigest()
        if committed != rebuilt:
            print(
                "css/app.css is stale: rebuilding it from css/tailwind.css and the markup "
                f"produces different bytes ({committed[:12]} committed, {rebuilt[:12]} rebuilt).\n"
                "Run: python frontend/build_css.py, and commit the result.",
                file=sys.stderr,
            )
            return 1
    finally:
        fresh.unlink(missing_ok=True)
    print(f"css/app.css is up to date ({committed[:12]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
