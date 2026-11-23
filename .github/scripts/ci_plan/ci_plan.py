#!/usr/bin/env python3
"""Select PR work without hiding required checks behind workflow path filters.

Unknown paths, unavailable history and every non-PR event run all work. The
workflow runs the base commit's copy, so a PR cannot change its own classifier.
Renames are read as delete/add pairs: both sides can affect different jobs.
"""

import os
import re
import subprocess

JOBS = ("lint", "tests", "doc", "msrv", "debian", "supply", "freshness", "folder", "lines")
RUST = {"lint", "tests", "doc", "msrv"}
ALWAYS = {"lines", "folder"}
BUILD = RUST | {"debian"}
OWN = {".github/scripts/ci_plan/ci_plan.py", ".github/scripts/ci_plan/test_ci_plan.py",
       ".github/scripts/ci_plan/__init__.py",
       ".github/workflows/reusable-ci-plan.yml"}
WORKFLOWS = {
    "ci.yml": RUST | {"freshness", "debian", "supply", "lines"},
    "reusable-rust-ci.yml": RUST,
    "reusable-rust-debian.yml": {"debian"},
    "reusable-rust-supply-chain.yml": {"supply"},
    "reusable-dependabot-freshness.yml": {"freshness"},
    "reusable-line-limit.yml": {"lines"},
}
TEST_FILE = re.compile(r"(?:^tests?(?:_[a-z0-9_]+)?$|_tests(?:_[a-z0-9_]+)?$|^test_support$)")


def test_only(path):
    """Only conventions already excluded by the integration workflows."""
    if path.startswith("tests/"):
        return True
    if not path.startswith("src/") or not path.endswith(".rs"):
        return False
    parts = path.split("/")
    return "tests" in parts[:-1] or bool(TEST_FILE.search(parts[-1][:-3]))


def affected(path):
    """Jobs that consume this path; an unrecognised path runs everything."""
    if path in OWN:
        return set(JOBS)
    if path.startswith(".github/workflows/"):
        # Rust tests assert workflow pins, coverage exclusions and packaging
        # contracts. Even a workflow unrelated to compilation can affect them.
        return WORKFLOWS.get(path.rsplit("/", 1)[-1], set(JOBS)) | {"tests"}
    if path in {"Cargo.toml", "Cargo.lock"} or path.startswith(".cargo/"):
        return BUILD | {"supply", "freshness"}
    if path.startswith("rust-toolchain") or path == "build.rs":
        return BUILD | {"supply"}
    if test_only(path):
        return {"lint", "tests"}
    if path.startswith(("src/", "migrations/", ".sqlx/")):
        return BUILD
    if path.startswith(("benches/", "examples/")):
        return {"lint", "tests"}
    if path.startswith("debian/"):
        return {"debian", "tests"}
    if path in {"about.toml", "about.hbs", "deny.toml", "LICENSE"}:
        return {"supply"}
    if path == "rustfmt.toml" or path.startswith(".clippy"):
        return {"lint"}
    if path == ".github/dependabot.yml":
        return {"freshness"}
    if path == ".github/folder-limit-exceptions.txt" or path.startswith("scripts/folder-limit/"):
        return set()  # the folder gate runs on every pull request
    if path.startswith("fuzz/"):
        return {"lint"}  # lint checks the separate fuzz lockfile with metadata
    if path.startswith((".github/scripts/", "scripts/", "deploy/")):
        return {"tests"}  # repository and packaging contract tests read these
    if path.startswith("docs/"):
        return {"tests"}  # tests read docs/configuration.md, cli.md, headers.md and more
    if path.endswith(".md"):
        return set()
    if path in {".gitignore", ".editorconfig", ".containerignore", "Containerfile"}:
        return set()
    return set(JOBS)


def select(event, changes):
    """Return booleans keyed by job, with non-PR events deliberately ungated."""
    if event != "pull_request" or not changes:
        return dict.fromkeys(JOBS, True)
    chosen = set()
    for _status, path in changes:
        chosen |= affected(path)
    # These two judge the whole tree and not the diff, so they always run.
    chosen |= ALWAYS
    return {job: job in chosen for job in JOBS}


def changed_paths(base, head):
    """NUL delimiters preserve whitespace; no rename detection hides old paths."""
    if not base or not head:
        raise ValueError("missing PR base or head")
    out = subprocess.check_output(
        ["git", "diff", "--name-status", "--no-renames", "-z", f"{base}...{head}"]
    ).decode("utf-8")
    fields = out.split("\0")
    if fields.pop() != "" or len(fields) % 2:
        raise ValueError("malformed git diff")
    changes = list(zip(fields[::2], fields[1::2]))
    if any(status not in {"A", "D", "M", "T"} or not path for status, path in changes):
        raise ValueError("unexpected git diff status or path")
    return changes


def main():
    event = os.environ.get("EVENT_NAME", "")
    try:
        changes = changed_paths(os.environ.get("BASE_SHA"), os.environ.get("HEAD_SHA")) if event == "pull_request" else []
        plan = select(event, changes)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"::warning::cannot narrow CI work: {error}; running everything")
        plan = dict.fromkeys(JOBS, True)
    lines = "".join(f"{job}={str(run).lower()}\n" for job, run in plan.items())
    print(lines, end="")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(lines)


if __name__ == "__main__":
    main()
