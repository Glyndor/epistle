#!/usr/bin/env python3
"""Fail unless everything the CodeQL configuration leaves out is provably test code.

    check_paths.py <config> --production <cargo-json>... --tests <cargo-json>...

Run from the root of the repository. The inputs are the outputs of `cargo check --locked
--message-format=json`: the production targets (`--lib --bins`, debug and `--release`, with the default
features and with `--all-features`) and the tests (`--tests --all-features`). The verdict is the
compiler's dep-info (`dep_info.py`); the tracked files come from `git ls-files -z`.

A pattern fails when it matches no tracked file, and when a Rust file it matches is
  - read by a production build (it is production code), or
  - not read by the test build (nothing proves it is only tests: a file for another operating
    system, behind a feature that is not switched on, or one that no target compiles).
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_yaml  # noqa: E402
from ci_codeql import dep_info, globs  # noqa: E402


def tracked(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    return [name.decode("utf-8", "surrogateescape") for name in out.split(b"\0") if name]


def problems(patterns, production, tests, files):
    found = []
    for pattern in patterns:
        hit = sorted(f for f in files if globs.matches(pattern, f))
        if not hit:
            found.append(f"{pattern} matches no file of the repository: it is a dead pattern")
        for kind, bad in (
            ("is read by a production build", [f for f in hit if f.endswith(".rs") and f in production]),
            ("is not read by the test build, so nothing proves it is only tests",
             [f for f in hit if f.endswith(".rs") and f not in production and f not in tests]),
        ):
            if bad:
                found.append(f"{pattern} leaves out {len(bad)} Rust file(s) whose first is {bad[0]}, which {kind}")
    return found


def split(argv):
    groups, current = {"--production": [], "--tests": []}, None
    for arg in argv:
        if arg in groups:
            current = arg
        elif current is None:
            return None
        else:
            groups[current].append(arg)
    return groups if all(groups.values()) else None


def main(argv):
    groups = split(argv[2:]) if len(argv) > 2 else None
    if groups is None:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path.cwd()
    try:
        patterns = ci_yaml.load(argv[1])["paths-ignore"]
        sets = {}
        for flag, is_tests in (("--production", False), ("--tests", True)):
            sets[flag] = set()
            for name in groups[flag]:
                sets[flag] |= dep_info.production_files(Path(name).read_text().splitlines(), root, tests=is_tests)
        found = problems(patterns, sets["--production"], sets["--tests"], tracked(root))
    except (dep_info.DepInfoError, KeyError, OSError, subprocess.CalledProcessError) as err:
        found = [f"could not check: {err}"]
    for line in found:
        print(f"::error::{line}")
    if not found:
        print(f"{len(sets['--production'])} files of the production builds and {len(sets['--tests'])} of the tests; "
              f"{len(patterns)} patterns leave out only files the tests alone read")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
