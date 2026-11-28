"""The reference copy of the CI files whose behaviour the gate rests on, compared by equality.

A check on the shape of a workflow (a name here, an `if` there) lets through what
it does not look at: a `shell:` that exits before the script, a `continue-on-error`,
a default that changes the working directory, a run line that echoes the command
it should have run. The files below are parsed and compared whole against a copy
kept under `.github/ci-contract/`, so any property nobody listed turns the test
red. Comments are not part of the parse.

The only thing normalised is the value of a pin: the commit of an action and the
digest of an image. Dependabot moves those and cannot regenerate the copy, so a
bump passes; renaming the action, dropping the pin, pointing at a tag or changing
the repository of an image does not.

To change a file on purpose, change it and run
`python3 .github/scripts/ci_contract/snapshot.py`, and review the copy in the diff.
"""

import json
import re
from pathlib import Path

import ci_yaml

FILES = (
    ".github/workflows/ci.yml",
    ".github/workflows/dco.yml",
    ".github/workflows/main-guard.yml",
    ".github/workflows/repository-health.yml",
    ".github/workflows/reusable-ci-plan.yml",
    ".github/workflows/reusable-cancel-others.yml",
    ".github/workflows/reusable-dco.yml",
    ".github/workflows/reusable-deprecation-notices.yml",
    ".github/workflows/reusable-dependabot-freshness.yml",
    ".github/workflows/reusable-line-limit.yml",
    ".github/workflows/reusable-main-guard.yml",
    ".github/workflows/reusable-rust-audit.yml",
    ".github/workflows/reusable-rust-ci.yml",
    ".github/workflows/reusable-rust-debian.yml",
    ".github/workflows/reusable-rust-supply-chain.yml",
    ".github/actions/rust-cache/action.yml",
)
FOLDER = Path(".github/ci-contract")
ACTION_PIN = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@[0-9a-f]{40}$")
IMAGE_PIN = re.compile(r"@sha256:[0-9a-f]{64}")


def normalize(value):
    """The parsed file with the value of each pin replaced and nothing else touched."""
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        match = ACTION_PIN.match(value)
        if match:
            return f"{match.group(1)}@PIN"
        return IMAGE_PIN.sub("@sha256:PIN", value)
    return value


def current(root, relative):
    return normalize(ci_yaml.load(Path(root) / relative))


def reference_path(root, relative):
    return Path(root) / FOLDER / (Path(relative).name + ".json")


def reference(root, relative):
    return json.loads(reference_path(root, relative).read_text())


def dump(value):
    return json.dumps(value, indent=1, sort_keys=True) + "\n"


def write_all(root):
    folder = Path(root) / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    for stale in folder.glob("*.json"):
        stale.unlink()
    for relative in FILES:
        reference_path(root, relative).write_text(dump(current(root, relative)))
