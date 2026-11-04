"""Filesystem secret guards for clones and git-archive workstation checkouts.

Operational secrets and generated trees are excluded explicitly. All other regular
files are scanned, including ignored files outside these directories. Symlinks are
not followed: a source scan must not read arbitrary files outside the checkout.
"""
import argparse
import os
from pathlib import Path
import re
from xml.etree.ElementTree import ParseError

from opnsense_seed import looks_secret

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIRS = {".git", ".state", "secrets", ".terraform", "__pycache__"}
PATTERNS = {
    "token": re.compile(rb"[A-Za-z0-9_-]+@[a-z]+![A-Za-z0-9_-]+=[0-9a-f]{8}-[0-9a-f]{4}-"),
    "key": re.compile(rb"BEGIN (OPENSSH|RSA|EC) PRIVATE KEY|AGE-" + rb"SECRET-KEY"),
}


def source_files():
    def unreadable(error):
        raise error

    for directory, dirs, files in os.walk(ROOT, onerror=unreadable):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS]
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file() or path == ROOT / "tests/static-checks.sh":
                continue
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["token", "key", "xml"])
    kind = parser.parse_args().kind
    leaked = False
    for path in source_files():
        if kind == "xml" and path.suffix != ".xml":
            continue
        data = path.read_bytes()
        if kind == "xml":
            try:
                found = looks_secret(data)
            except ParseError:
                continue
        else:
            found = PATTERNS[kind].search(data)
        if found:
            # Identify the file, never print its secret contents.
            print("FAIL secret material in " + str(path.relative_to(ROOT)))
            leaked = True
    return int(leaked)


if __name__ == "__main__":
    raise SystemExit(main())
