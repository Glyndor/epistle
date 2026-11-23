"""The one way the CI tests and scripts read workflows and actions.

A reader built on regular expressions skips the lines it does not recognise,
and GitHub runs what the reader skipped; PyYAML's safe loader keeps the last of
two equal keys, and GitHub reads the same file differently. So the files are
parsed, a duplicate key is an error, and one function lists what there is to
read: `.yml` and `.yaml` under `.github/workflows`, and every `action.yml` or
`action.yaml` anywhere in the tree.
"""

import subprocess
from pathlib import Path

import yaml

SUFFIXES = (".yml", ".yaml")
ACTION_NAMES = ("action.yml", "action.yaml")
SKIP_DIRS = {".git", "target", "node_modules", "vendor"}


class StrictLoader(yaml.SafeLoader):
    """A safe loader that refuses a mapping with the same key twice."""


def _mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def loads(text):
    return yaml.load(text, Loader=StrictLoader)  # noqa: S506 - a safe loader


def load(path):
    return loads(Path(path).read_text())


def workflow_files(root):
    """Every workflow file, whatever its suffix and however deep."""
    folder = Path(root) / ".github" / "workflows"
    return sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix in SUFFIXES)


def action_files(root):
    """Every composite or local action definition in the tree."""
    found = []
    for path in Path(root).rglob("*"):
        if path.name in ACTION_NAMES and path.is_file() and not SKIP_DIRS & set(path.relative_to(root).parts):
            found.append(path)
    return sorted(found)


def tracked(root):
    """The files git tracks, for tests that must not depend on what happens to be on disk."""
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [p for p in out.decode().split("\0") if p]
