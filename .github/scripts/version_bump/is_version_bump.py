#!/usr/bin/env python3
"""Say whether a pull request is nothing but an epistle version bump.

Usage: is_version_bump.py BASE HEAD

Exit 0 only when the change the pull request makes (from the merge base of
BASE and HEAD to HEAD) is a pure version bump, so the workflows that are not
required can skip it. Exit 1 for anything else, including every error: this
answer lets a pull request past jobs that would otherwise run, so it fails
closed. A release bump touches Cargo.toml, both lockfiles, debian/changelog
and the image tags in the docs. The content of each file is checked, not only
its name, because Cargo.toml and Cargo.lock also carry dependency changes.

Every condition is mandatory:
  a. at least one file changed, and every one is Cargo.toml, Cargo.lock,
     fuzz/Cargo.lock, debian/changelog or a Markdown file under docs/.
  b. Cargo.toml changed. Its first `version = ...` line sits inside
     [package], reads `version = "X.Y.Z"` on both sides, and the file is
     otherwise identical. That gives the old and the new version.
  c. each changed lockfile has exactly one `name = "epistle"` package whose
     next line goes from the old version to the new one, and nothing else
     in the file changed.
  d. debian/changelog is the old file with whole lines put in front of it,
     and its first line opens the entry of the new version.
  e. a changed Markdown file under docs/ keeps its line count, and every line
     that changed is the old line with the old version replaced by the new.

The workflows run the copy of this file that is in the base commit, so a pull
request cannot rewrite the judge of its own diff. It uses the standard library
only and is run with `python3 -I`.
"""

import re
import subprocess
import sys

PACKAGE = "epistle"
SEMVER = re.compile(r'version = "([0-9]+\.[0-9]+\.[0-9]+)"')
VERSION_LINE = re.compile(r"version\s*=")
LOCKFILES = ("Cargo.lock", "fuzz/Cargo.lock")
CHANGELOG = "debian/changelog"


class NotABump(Exception):
    """The range is not a pure version bump; the message says why."""


def git(*args):
    try:
        done = subprocess.run(["git", *args], capture_output=True, check=False)
    except OSError as err:
        raise NotABump(f"cannot run git: {err}") from err
    if done.returncode != 0:
        raise NotABump(f"git {' '.join(args)} failed")
    return done.stdout


def show(rev, path, label):
    try:
        return git("show", f"{rev}:{path}").decode("utf-8")
    except NotABump as err:
        raise NotABump(f"{path} is missing in {label}") from err
    except UnicodeDecodeError as err:
        raise NotABump(f"{path} in {label} is not UTF-8") from err


def plain(line, path, label):
    match = SEMVER.fullmatch(line)
    if not match:
        raise NotABump(f"{path} version in {label} is not plain X.Y.Z")
    return match.group(1)


def manifest_version(text, label):
    """The [package] version of Cargo.toml and the file with it blanked."""
    lines = text.split("\n")
    section = None
    for index, line in enumerate(lines):
        if line.startswith("["):
            section = line.strip()
        if VERSION_LINE.match(line):
            if section != "[package]":
                raise NotABump(f"Cargo.toml in {label} has no usable version line")
            version = plain(line, "Cargo.toml", label)
            lines[index] = ""
            return version, lines
    raise NotABump(f"Cargo.toml in {label} has no usable version line")


def lock_version(text, path, label):
    """The version of the one epistle package in a lockfile, and the rest."""
    lines = text.split("\n")
    marks = [i for i, line in enumerate(lines) if line == f'name = "{PACKAGE}"']
    if len(marks) != 1 or marks[0] + 1 >= len(lines):
        raise NotABump(f"{path} in {label} has no usable version line")
    index = marks[0] + 1
    if not VERSION_LINE.match(lines[index]):
        raise NotABump(f"{path} in {label} has no usable version line")
    version = plain(lines[index], path, label)
    lines[index] = ""
    return version, lines


def check_changelog(old_text, new_text, new):
    if not old_text:
        raise NotABump(f"{CHANGELOG} is empty in the base")
    if len(new_text) <= len(old_text):
        raise NotABump(f"{CHANGELOG} did not grow")
    if not new_text.endswith(old_text):
        raise NotABump(f"{CHANGELOG} edits or removes an earlier line")
    added = new_text[: len(new_text) - len(old_text)]
    if not added.endswith("\n"):
        raise NotABump(f"{CHANGELOG} adds a partial line")
    if not added.startswith(f"{PACKAGE} ({new}) "):
        raise NotABump(f"{CHANGELOG} does not start with the {PACKAGE} {new} entry")


def check_doc(path, old_text, new_text, old, new):
    old_lines = old_text.split("\n")
    new_lines = new_text.split("\n")
    if len(old_lines) != len(new_lines):
        raise NotABump(f"{path} adds or removes lines")
    for before, after in zip(old_lines, new_lines, strict=True):
        if before != after and before.replace(old, new) != after:
            raise NotABump(f"{path} changes more than the version")


def judge(base, head):
    """Return (old, new) for a pure bump, raise NotABump otherwise."""
    for rev in (base, head):
        git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    fork = git("merge-base", base, head).decode().strip()
    names = git("diff", "--name-only", "--no-renames", "-z", fork, head).decode()
    changed = [name for name in names.split("\0") if name]
    if not changed:
        raise NotABump("empty range")
    for name in changed:
        if name in ("Cargo.toml", CHANGELOG, *LOCKFILES):
            continue
        if name.startswith("docs/") and name.endswith(".md"):
            continue
        raise NotABump(f"{name} is not part of a version bump")
    if "Cargo.toml" not in changed:
        raise NotABump("Cargo.toml does not change the version")

    old, old_rest = manifest_version(show(fork, "Cargo.toml", "the base"), "the base")
    new, new_rest = manifest_version(show(head, "Cargo.toml", "head"), "head")
    if old_rest != new_rest:
        raise NotABump("Cargo.toml changes more than the version")

    for name in changed:
        before = show(fork, name, "the base")
        after = show(head, name, "head")
        if name in LOCKFILES:
            was, old_rest = lock_version(before, name, "the base")
            now, new_rest = lock_version(after, name, "head")
            if (was, now) != (old, new):
                raise NotABump(f"{name} does not move {PACKAGE} from {old} to {new}")
            if old_rest != new_rest:
                raise NotABump(f"{name} changes more than the version")
        elif name == CHANGELOG:
            check_changelog(before, after, new)
        elif name != "Cargo.toml":
            check_doc(name, before, after, old, new)
    return old, new


def main(argv):
    if len(argv) != 3:
        print("not a pure version bump: usage: is_version_bump.py BASE HEAD", file=sys.stderr)
        return 1
    try:
        old, new = judge(argv[1], argv[2])
    except NotABump as err:
        print(f"not a pure version bump: {err}", file=sys.stderr)
        return 1
    except Exception as err:  # noqa: BLE001 - any failure means "not a bump"
        print(f"not a pure version bump: unexpected error: {err!r}", file=sys.stderr)
        return 1
    print(f"a pure version bump: {old} -> {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
