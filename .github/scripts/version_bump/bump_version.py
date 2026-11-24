#!/usr/bin/env python3
"""Bump the version of epistle everywhere it is stamped, and nowhere else.

Usage: bump_version.py NEW --changelog FILE [--date "Tue, 24 Nov 2026 12:00:00 +0000"] [--root DIR] [--cargo-check]

What carries the version of the package, found by reading what the previous release left and not by copying its diff:

  Cargo.toml          the `version` of `[package]` (a dependency may carry the same number: reqwest 0.13.4
                      sat beside epistle 0.13.4, and is not touched)
  Cargo.lock          the one `name = "epistle"` package
  fuzz/Cargo.lock     the same
  debian/changelog    a new entry in front of the old ones; `dpkg-buildpackage` takes the `.deb` version from it
  docs/**/*.md        the image tags of this release (`ghcr.io/glyndor/epistle:X.Y.Z`, `...:X.Y.Z-amd64`,
                      `...:X.Y.Z-arm64`, and the short `...:X.Y.Z-arm64` form that begins with an ellipsis);
                      the floating tags (`:0.13`, `:0`) are not this release's and stay

The change it makes has to be the one `is_version_bump.py` calls a pure version bump, and `--cargo-check` asks cargo
(`metadata --locked --offline`, which compiles nothing) whether both lockfiles are what the manifests need. The
changelog file holds the bullets, one per line, each starting with `* `.

Nothing is written unless every file has exactly the one place to change.
"""

import argparse
import email.utils
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
LOCKFILES = ("Cargo.lock", "fuzz/Cargo.lock")
MAINTAINER = "Glyndor <packages@glyndor.net>"


class Refused(Exception):
    pass


def version_tuple(text, what):
    match = SEMVER.fullmatch(text)
    if not match:
        raise Refused(f"{what} {text!r} is not a plain X.Y.Z")
    return tuple(int(part) for part in match.groups())


def package_version(manifest):
    section, found = None, []
    for index, line in enumerate(manifest.split("\n")):
        if line.startswith("["):
            section = line.strip()
        match = re.fullmatch(r'version = "([^"]*)"', line)
        if match and section == "[package]":
            found.append((index, match.group(1)))
    if len(found) != 1:
        raise Refused(f"Cargo.toml has {len(found)} `version` lines in [package], one was expected")
    return found[0]


def bump_manifest(text, old, new):
    index, current = package_version(text)
    if current != old:
        raise Refused(f"Cargo.toml says {current}, not {old}")
    lines = text.split("\n")
    lines[index] = f'version = "{new}"'
    return "\n".join(lines)


def bump_lock(text, path, old, new):
    lines = text.split("\n")
    marks = [i for i, line in enumerate(lines) if line == 'name = "epistle"']
    if len(marks) != 1:
        raise Refused(f"{path} has {len(marks)} packages named epistle, one was expected")
    at = marks[0] + 1
    if lines[at] != f'version = "{old}"':
        raise Refused(f"{path} has epistle at {lines[at]}, not {old}")
    lines[at] = f'version = "{new}"'
    return "\n".join(lines)


def entry(new, bullets, date):
    body = "".join(f"  * {line}\n" for line in bullets)
    return f"epistle ({new}) unstable; urgency=medium\n\n{body}\n -- {MAINTAINER}  {date}\n\n"


def bump_changelog(text, new, old, bullets, date):
    first = text.split("\n", 1)[0]
    if not first.startswith(f"epistle ({old}) "):
        raise Refused(f"debian/changelog starts with {first!r}, not the entry of {old}")
    return entry(new, bullets, date) + text


def image_tags(old):
    """The references to this release's image in a docs page: with the registry or with the ellipsis, with an architecture or without."""
    return re.compile(rf"((?:ghcr\.io/glyndor/epistle|…):){re.escape(old)}(?=(?:-amd64|-arm64)?(?![0-9A-Za-z.-]))")


def bump_doc(text, old, new):
    return image_tags(old).sub(lambda m: m.group(1) + new, text)


def bullets_of(path):
    lines = [line.rstrip("\n") for line in Path(path).read_text(encoding="utf-8").split("\n") if line.strip()]
    if not lines:
        raise Refused("the changelog file has no bullet")
    out = []
    for line in lines:
        if not line.startswith("* "):
            raise Refused(f"a bullet of the changelog file does not start with '* ': {line[:40]!r}")
        out.append(line[2:])
    return out


def plan(root, new, bullets, date):
    """{relative path: new text} for every file that changes; raises Refused before anything is written."""
    root = Path(root)
    manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
    old = package_version(manifest)[1]
    if version_tuple(new, "the new version") <= version_tuple(old, "the current version"):
        raise Refused(f"{new} does not come after {old}")
    changes = {"Cargo.toml": bump_manifest(manifest, old, new)}
    for lock in LOCKFILES:
        changes[lock] = bump_lock((root / lock).read_text(encoding="utf-8"), lock, old, new)
    changes["debian/changelog"] = bump_changelog((root / "debian/changelog").read_text(encoding="utf-8"), new, old, bullets, date)
    for path in sorted((root / "docs").rglob("*.md")):
        before = path.read_text(encoding="utf-8")
        after = bump_doc(before, old, new)
        if after != before:
            changes[path.relative_to(root).as_posix()] = after
    return old, changes


def cargo_check(root):
    for manifest in ("Cargo.toml", "fuzz/Cargo.toml"):
        if not (Path(root) / manifest).exists():
            continue
        done = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", manifest],
                              cwd=root, capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise Refused(f"{manifest}: cargo says the lockfile is not what the manifest needs:\n{done.stderr.strip()[-400:]}")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("new")
    parser.add_argument("--changelog", required=True)
    parser.add_argument("--date")
    parser.add_argument("--root", default=".")
    parser.add_argument("--cargo-check", action="store_true")
    args = parser.parse_args(argv[1:])
    date = args.date or email.utils.format_datetime(datetime.now(timezone.utc).replace(microsecond=0)).replace("-0000", "+0000")
    try:
        old, changes = plan(args.root, args.new, bullets_of(args.changelog), date)
        for relative, text in changes.items():
            (Path(args.root) / relative).write_text(text, encoding="utf-8")
        if args.cargo_check:
            cargo_check(args.root)
    except Refused as err:
        print(f"not bumped: {err}", file=sys.stderr)
        return 1
    print(f"bumped {old} -> {args.new}: " + ", ".join(sorted(changes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
