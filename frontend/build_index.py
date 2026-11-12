from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAGE = HERE / "index.html"
ENTRY = "js/main.js"
STYLESHEET = "css/app.css"
VERSION_CHARS = 12
IMPORT = re.compile(r"""(?:\bfrom|\bimport)\s*["'](\.{1,2}/[^"']+)["']""")


def version(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:VERSION_CHARS]


def modules() -> list[str]:
    seen: set[str] = set()
    queue = [ENTRY]
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        source = (HERE / name).read_text(encoding="utf-8")
        for target in IMPORT.findall(source):
            queue.append(((HERE / name).parent / target).resolve().relative_to(HERE).as_posix())
    return sorted(seen)


def render(page: str) -> str:
    versions = {name: version(HERE / name) for name in modules()}
    page = re.sub(r'\n[ \t]*<script type="importmap">.*?</script>', "", page, flags=re.S)
    page = re.sub(r'\n[ \t]*<link rel="modulepreload"[^>]*>', "", page)
    page = re.sub(r'href="css/app\.css[^"]*"', f'href="{STYLESHEET}?v={version(HERE / STYLESHEET)}"', page)
    page = re.sub(r'src="js/main\.js[^"]*"', f'src="{ENTRY}?v={versions[ENTRY]}"', page)

    entries = [f'      "./{name}": "./{name}?v={digest}"' for name, digest in versions.items()]
    lines = ['  <script type="importmap">', "  {", '    "imports": {', ",\n".join(entries), "    }", "  }", "  </script>"]
    lines += [f'  <link rel="modulepreload" href="{name}?v={digest}">' for name, digest in versions.items()]

    anchor = re.search(r'^[ \t]*<link rel="stylesheet" href="css/app\.css[^>]*>$', page, flags=re.M)
    if anchor is None:
        raise SystemExit("index.html has no stylesheet link for css/app.css to anchor the script list to")
    return page[: anchor.end()] + "\n" + "\n".join(lines) + page[anchor.end() :]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List every dashboard script in index.html with a version taken from its content."
    )
    parser.add_argument("--check", action="store_true", help="write nothing; fail if index.html is out of date")
    args = parser.parse_args()

    raw = PAGE.read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    current = raw.replace("\r\n", "\n")
    fresh = render(current)
    count = len(modules())

    if args.check:
        if fresh != current:
            print(
                "index.html is stale: a script or the stylesheet changed since its versions were written.\n"
                "Run: python frontend/build_index.py, and commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"index.html is up to date ({count} scripts)")
        return 0

    PAGE.write_bytes(fresh.replace("\n", newline).encode("utf-8"))
    print(f"index.html written ({count} scripts, stylesheet {version(HERE / STYLESHEET)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
