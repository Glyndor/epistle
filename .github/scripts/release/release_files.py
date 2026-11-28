#!/usr/bin/env python3
"""The exact set of files a release has, worked out from the tag, and the check that a directory holds it.

The signing job, the job that attests and the job that publishes each receive a
directory somebody else filled. Counting files or accepting a pattern lets an
extra package, a package of another version or architecture, a link, a directory
or a hidden file through. Here the full list of names is derived from the tag
that `verify` accepted, and the directory has to equal it: nothing more, nothing
less, every entry a regular file.

Usage:
  release_files.py names <tag> <built|signed>
  release_files.py check <dir> <tag> <built|signed>
  release_files.py check-package <dir> <tag> <kind>
  release_files.py same-packages <dir> <tag> <kind>=<sha256> ...

`built` is what the build job hands over; `signed` adds one signature for each of
those. A kind is one package of the release: `amd64` and `arm64` for the .deb,
`rpm-x86_64` and `rpm-aarch64` for the rpm. A prerelease tag carries the .deb
only: the rpm channel serves tags of three numbers and refuses anything else.
`check` also reads the control fields of the .deb packages with `dpkg-deb` (the
other formats are read where they are built, and held here by their digest) and
recomputes SHA256SUMS. It prints one `error:` line per problem and exits 1. It
runs with `python3 -I` and needs nothing installed.
"""

import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

TAG = re.compile(r"^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?)$")
ARCHES = ("amd64", "arm64")
RPM_ARCHES = ("x86_64", "aarch64")
STAGES = ("built", "signed")


def version_of(tag):
    match = TAG.match(tag)
    if not match:
        raise ValueError(f"{tag!r} is not a release tag of the form vMAJOR.MINOR.PATCH")
    return match.group(1)


def package_name(tag, arch):
    return f"epistle_{version_of(tag)}_{arch}.deb"


def packages(tag):
    """Every package of the release of this tag, as {kind: file name}."""
    version = version_of(tag)
    found = {arch: package_name(tag, arch) for arch in ARCHES}
    if "-" not in version:
        for arch in RPM_ARCHES:
            found[f"rpm-{arch}"] = f"epistle-{version}-1.glyndor.any.{arch}.rpm"
    return found


def built_names(tag):
    return sorted(
        [f"epistle-{tag}-x86_64-linux", f"epistle-{tag}.cdx.json", "SHA256SUMS", *packages(tag).values()]
    )


def names(tag, stage):
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}")
    built = built_names(tag)
    return built if stage == "built" else sorted(built + [f"{name}.sig" for name in built])


def entries(directory):
    """Every entry under the directory, hidden ones and nested ones included, with its kind."""
    root = Path(directory)
    found = {}
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        found[path.relative_to(root).as_posix()] = "file" if stat.S_ISREG(mode) else "not a regular file"
    return found


KEY_VARIABLES = ("GLYNDOR_RELEASE_ED25519_KEY",)


def clean_environment():
    """The environment a parser of untrusted bytes gets: without the signing key, whoever set it."""
    return {name: value for name, value in os.environ.items() if name not in KEY_VARIABLES}


def control_field(deb, field):
    done = subprocess.run(["dpkg-deb", "--field", str(deb), field], capture_output=True, text=True, check=False,
                          env=clean_environment())
    return done.stdout.strip() if done.returncode == 0 else None


def check(directory, tag, stage):
    problems = []
    wanted = names(tag, stage)
    held = entries(directory)
    for name in sorted(set(held) - set(wanted)):
        problems.append(f"unexpected entry: {name}")
    for name in sorted(set(wanted) - set(held)):
        problems.append(f"missing: {name}")
    for name, kind in sorted(held.items()):
        if kind != "file":
            problems.append(f"{name} is {kind}")
    if problems:
        return problems
    root = Path(directory)
    version = version_of(tag)
    for arch in ARCHES:
        deb = root / package_name(tag, arch)
        for field, want in (("Package", "epistle"), ("Version", version), ("Architecture", arch)):
            got = control_field(deb, field)
            if got != want:
                problems.append(f"{deb.name}: {field} is {got!r}, expected {want!r}")
    listed = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})[ *]+(.+)", line)
        if not match:
            problems.append(f"SHA256SUMS has a line that is not a hash and a name: {line!r}")
            continue
        listed[match.group(2)] = match.group(1)
    expected = sorted(n for n in built_names(tag) if n != "SHA256SUMS")
    if sorted(listed) != expected:
        problems.append("SHA256SUMS does not name exactly the built files")
    for name, digest in sorted(listed.items()):
        if name in expected and hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            problems.append(f"{name} does not match its hash in SHA256SUMS")
    if stage == "signed":
        for name in built_names(tag):
            if (root / f"{name}.sig").stat().st_size == 0:
                problems.append(f"{name}.sig is empty")
    return problems


def check_package(directory, tag, kind):
    """A directory that holds exactly one package, the one this tag names for this kind."""
    wanted = packages(tag)
    if kind not in wanted:
        return [f"a release of {tag} has no package of the kind {kind!r}"]
    root = Path(directory)
    name = wanted[kind]
    held = entries(root)
    problems = [f"unexpected entry: {n}" for n in sorted(set(held) - {name})]
    if name not in held:
        return problems + [f"missing: {name}"]
    if held[name] != "file":
        return problems + [f"{name} is {held[name]}"]
    if kind in ARCHES:
        version = version_of(tag)
        for field, want in (("Package", "epistle"), ("Version", version), ("Architecture", kind)):
            got = control_field(root / name, field)
            if got != want:
                problems.append(f"{name}: {field} is {got!r}, expected {want!r}")
    return problems


def same_packages(directory, tag, digests):
    """The gathered packages are byte for byte the ones their builders handed over."""
    problems = []
    for kind, name in packages(tag).items():
        want = digests.get(kind, "")
        if not re.fullmatch(r"[0-9a-f]{64}", want):
            problems.append(f"{kind}: the digest handed over is not a SHA-256: {want!r}")
            continue
        path = Path(directory) / name
        if not path.is_file() or path.is_symlink():
            problems.append(f"{path.name} is missing or not a regular file")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != want:
            problems.append(f"{path.name} is not the package its builder produced")
    return problems


def main(argv):
    try:
        if len(argv) == 4 and argv[1] == "names":
            print("\n".join(names(argv[2], argv[3])))
            return 0
        if len(argv) == 5 and argv[1] == "check-package":
            problems = check_package(argv[2], argv[3], argv[4])
            for problem in problems:
                print(f"error: {problem}")
            if not problems:
                print(f"{argv[2]} holds exactly the {argv[4]} package of {argv[3]}")
            return 1 if problems else 0
        if len(argv) >= 5 and argv[1] == "same-packages":
            pairs = dict(item.split("=", 1) for item in argv[4:])
            problems = same_packages(argv[2], argv[3], pairs)
            for problem in problems:
                print(f"error: {problem}")
            return 1 if problems else 0
        if len(argv) == 5 and argv[1] == "check":
            problems = check(argv[2], argv[3], argv[4])
            for problem in problems:
                print(f"error: {problem}")
            if not problems:
                print(f"{argv[2]} holds exactly the {argv[4]} files of {argv[3]}")
            return 1 if problems else 0
    except (ValueError, OSError) as err:
        print(f"error: {err}")
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
