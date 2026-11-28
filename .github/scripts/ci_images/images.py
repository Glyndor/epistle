#!/usr/bin/env python3
"""The container images of the workflows and of the package builders, compared with the Dockerfile Dependabot watches.

    images.py check   exit 1 and say which reference disagrees
    images.py sync    copy the digests of `.github/ci-images/Dockerfile` into the files that name them

Dependabot reads the `FROM` lines of a Dockerfile and not the `image:` or `container:` of a
workflow, so the digests of the images the workflows run drifted unseen. They are kept in
`.github/ci-images/Dockerfile`, and a reference in a workflow, or in the file of the images the
package builders run, is the same image by name and the same digest. The tag of a reference may
be missing in a workflow (a digest alone is a reference); the name and the digest are what is
compared. A line that is a comment names no image that runs.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / ".github/ci-images/Dockerfile"
# The files besides the workflows that name an image something runs.
OTHERS = (".github/scripts/distro_packages/images.env",)
REFERENCE = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._/-]*)(?P<tag>:[A-Za-z0-9._-]+)?@sha256:(?P<digest>[0-9a-f]{64})")
FROM = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.M)


def short(name):
    """`docker.io/library/rust` and `rust` are the same image; so are `docker.io/dovecot/imaptest` and `dovecot/imaptest`."""
    for prefix in ("docker.io/", "library/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


def dockerfile(path=DOCKERFILE):
    """[(short name, tag, digest, alias)] of the lines of the Dockerfile; a line that is not a pinned `FROM` is an error."""
    found = []
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = FROM.match(line)
        ref = REFERENCE.fullmatch(match.group(1)) if match else None
        if not ref:
            raise ValueError(f"not a pinned FROM line: {line!r}")
        entry = (short(ref["name"]), (ref["tag"] or "")[1:] or None, ref["digest"], match.group(2))
        if any(e[:2] == entry[:2] for e in found):
            raise ValueError(f"{entry[0]}:{entry[1]} appears twice")
        found.append(entry)
    return found


def lookup(pinned, name, tag):
    """The entries a reference can mean: its name and its tag, or its name alone when it has no tag."""
    return [e for e in pinned if e[0] == name and (tag is None or e[1] == tag)]


def sources(root=ROOT):
    """The files that name images: the workflows and the others that exist."""
    workflows = sorted(Path(root, ".github/workflows").glob("*.y*ml"))
    return workflows + [Path(root, name) for name in OTHERS if Path(root, name).is_file()]


def references(root=ROOT):
    """[(path, short name, tag or None, digest)] of every image reference with a digest in those files."""
    out = []
    for path in sources(root):
        for line in path.read_text().splitlines():
            code = "" if line.lstrip().startswith("#") else line.split(" #", 1)[0]
            for ref in REFERENCE.finditer(code):
                out.append((path, short(ref["name"]), (ref["tag"] or "")[1:] or None, ref["digest"]))
    return out


def problems(root=ROOT, path=DOCKERFILE):
    pinned = dockerfile(path)
    found = references(root)
    problems = []
    for workflow, name, tag, digest in found:
        entries = lookup(pinned, name, tag)
        shown = f"{name}:{tag}" if tag else name
        if len(entries) != 1:
            why = "which the Dockerfile does not list" if not entries else "which more than one line of the Dockerfile could be"
            problems.append(f"{workflow.name} runs {shown}@sha256:{digest[:12]}, {why}")
        elif entries[0][2] != digest:
            problems.append(f"{workflow.name} runs {shown} at sha256:{digest[:12]} and the Dockerfile has sha256:{entries[0][2][:12]}")
    for name, tag, _, alias in pinned:
        if not any(n == name and (t is None or t == tag) for _, n, t, _ in found):
            problems.append(f"the Dockerfile lists {name}:{tag} ({alias}) and nothing runs it")
    return problems


def sync(root=ROOT, path=DOCKERFILE):
    """Rewrite the digests of those files to the ones of the Dockerfile; returns the files changed."""
    pinned = dockerfile(path)
    changed = []
    for workflow in sources(root):
        text = workflow.read_text()

        def replace(match):
            tag = match["tag"][1:] if match["tag"] else None
            entries = lookup(pinned, short(match["name"]), tag)
            if len(entries) != 1:
                return match.group(0)
            return f"{match['name']}{match['tag'] or ''}@sha256:{entries[0][2]}"

        new = REFERENCE.sub(replace, text)
        if new != text:
            workflow.write_text(new)
            changed.append(workflow)
    return changed


def main(argv):
    if len(argv) != 2 or argv[1] not in ("check", "sync"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "sync":
        for path in sync():
            print(f"updated {path.relative_to(ROOT)}")
        return 0
    found = problems()
    for line in found:
        print(f"::error::{line}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
