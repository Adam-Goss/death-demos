"""Filesystem secret guards for clones and git-archive workstation checkouts.

The basename and directory globs in this repo's .gitignore exclude operational
secrets and generated files. Unsupported ignore syntax fails the scan rather than
silently ignoring the wrong files. Symlinks and non-regular files are not followed.
"""
import argparse
from fnmatch import fnmatchcase
import os
from pathlib import Path
import re
from xml.etree.ElementTree import ParseError

from opnsense_seed import looks_secret

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "token": re.compile(rb"[A-Za-z0-9_-]+@[a-z]+![A-Za-z0-9_-]+=[0-9a-f]{8}-[0-9a-f]{4}-"),
    "key": re.compile(rb"BEGIN (OPENSSH|RSA|EC) PRIVATE KEY|AGE-" + rb"SECRET-KEY"),
}


def source_files():
    def unreadable(error):
        raise error

    # The repository uses only basename globs and unanchored directory names.
    # Fail closed if future rules need a fuller Git-ignore implementation.
    rules = [line.rstrip() for line in (ROOT / ".gitignore").read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    if any(rule[0].isspace() or rule.startswith("!") or "/" in rule.rstrip("/") or "\\" in rule
           for rule in rules):
        raise ValueError("unsupported .gitignore rule; update the filesystem scanner")
    directory_patterns = [rule.rstrip("/") for rule in rules] + [".git"]
    file_patterns = [rule for rule in rules if not rule.endswith("/")] + [".git"]
    for directory, dirs, files in os.walk(ROOT, onerror=unreadable):
        dirs[:] = [name for name in dirs if not any(fnmatchcase(name, pattern) for pattern in directory_patterns)]
        for name in files:
            path = Path(directory) / name
            if (any(fnmatchcase(name, pattern) for pattern in file_patterns)
                    or path.is_symlink() or not path.is_file()):
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
