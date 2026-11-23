#!/usr/bin/env python3
"""Name the Rust tests that read the files under `.github`.

A change to a workflow, a CI script or a repository template cannot break the
product, but it can break a test that reads those files (the toolchain pins,
the runner variable, the coverage exclusions, the Dependabot shape). Those
tests are a small part of the suite, so a change that only reaches them runs
them and not the whole suite with coverage.

The list is read from the tree, not kept by hand, so a new test that reads
`.github` joins it by being written:

- an integration test target is selected when its source, or a file it pulls in
  with `mod` or `#[path]`, mentions `.github`, or when it lives under
  `tests/repository/`, whose tests read the repository as a whole;
- a unit test in the library is selected by the module path of a file under
  `src/` that mentions `.github` outside a comment.

Prints `tests=<args>` and `lib=<filters>` for $GITHUB_OUTPUT. Names are checked
against a closed alphabet before they are printed.

Usage: wiring_targets.py [repo-root]
"""

import re
import sys
import tomllib
from pathlib import Path

MENTION = re.compile(r"\.github")
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)
NAME = re.compile(r"[A-Za-z0-9_]+")
ALWAYS = ("tests/repository/",)


def children(path):
    """Files a source file pulls in with `mod name;` or `#[path = "..."]`."""
    text = path.read_text(errors="replace")
    found = set()
    for rel in PATH_ATTR.findall(text):
        found.add((path.parent / rel).resolve())
    for name in MOD_DECL.findall(text):
        for base in (path.parent, path.parent / path.stem):
            found.update({(base / f"{name}.rs").resolve(), (base / name / "mod.rs").resolve()})
    return {child for child in found if child.is_file()}


def sources(root_file):
    """The root file of a target and everything it pulls in."""
    seen, todo = set(), [root_file.resolve()]
    while todo:
        current = todo.pop()
        if current in seen or not current.is_file():
            continue
        seen.add(current)
        todo.extend(children(current))
    return seen


def targets(root):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    chosen = []
    for entry in manifest.get("test", []):
        name, rel = entry["name"], entry["path"]
        if rel.startswith(ALWAYS) or any(MENTION.search(f.read_text(errors="replace")) for f in sources(root / rel)):
            chosen.append(name)
    return sorted(chosen)


def module_path(root, file):
    parts = list(file.relative_to(root / "src").with_suffix("").parts)
    if parts[-1] == "mod":
        parts.pop()
    return "::".join(parts)


def code_mentions(text):
    return any(MENTION.search(line) for line in text.splitlines() if not line.lstrip().startswith("//"))


def lib_filters(root):
    found = []
    for file in sorted((root / "src").rglob("*.rs")):
        if code_mentions(file.read_text(errors="replace")) and file.relative_to(root / "src").parts != ("lib.rs",):
            found.append(module_path(root, file))
    return found


def render(root):
    names = targets(root)
    filters = lib_filters(root)
    for name in (*names, *(part for f in filters for part in f.split("::"))):
        if not NAME.fullmatch(name):
            raise ValueError(f"unexpected name {name!r}")
    return {
        "tests": " ".join(f"--test {name}" for name in names),
        "lib": " ".join(filters),
    }


def main(argv):
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    for key, value in render(root).items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
