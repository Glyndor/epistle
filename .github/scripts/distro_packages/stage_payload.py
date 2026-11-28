#!/usr/bin/env python3
"""Stage the files of the epistle .deb for the packages of the other distributions.

The release builds the .deb once, from the pinned musl toolchain, and the other
packages are made from that payload, so they install the same bytes. This script
reads the .deb, checks it is the package it should be, and writes the tree the
builders pack.

    python3 -I stage_payload.py --deb FILE --version X.Y.Z --arch amd64|arm64 \
        --repository DIR --out DIR

`--repository` is the checkout that holds LICENSE and packaging/linux/.

The output directory receives `root/` (the tree), `files.txt` (one line per file:
`<octal mode> <path> <sha256> <size>`, sorted by path), `dirs.txt` (the
directories only this package uses) and `epoch` (the time of the binary in the
.deb, which every file and the package are stamped with). Nothing is executed
from the .deb. Standard library only; run it with `-I`.

It refuses, before writing anything, a .deb that is not exactly the expected
shape: other members, links, absolute or `..` paths, a file it does not know or
one that is missing, a binary of another architecture or one that asks for a
dynamic loader, a version that is not the one given, and a postinst it cannot
carry over.

What changes on the way, and nothing else:

- the zsh completion moves from Debian's `vendor-completions` to
  `site-functions`, which is where the other distributions look;
- the port floor moves from `/usr/lib/sysctl.d` to `/usr/lib/epistle/sysctl.d`,
  because the channels do not admit a package that installs there;
  `/usr/lib/epistle/setup` applies it;
- the copyright file goes to the licence directory, next to LICENSE;
- the postinst of the .deb is shipped as `/usr/lib/epistle/configure`, with the
  two things it says about Debian rewritten (see `carry_over`);
- `setup` and the sysusers.d entry from packaging/linux/ are added.
"""

import argparse
import hashlib
import io
import lzma
import os
import re
import sys
import tarfile

VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ARCHES = {"amd64": 62, "arm64": 183}  # the ELF machine of each

MAX_DEB = 300 * 1024 * 1024
MAX_MEMBER = 200 * 1024 * 1024

BINARY = "usr/bin/epistle"
SYSCTL_DEB = "usr/lib/sysctl.d/30-glyndor-epistle.conf"
SYSCTL = "usr/lib/epistle/sysctl.d/30-glyndor-epistle.conf"
MAN_RE = re.compile(r"usr/share/man/man1/epistle(-[a-z0-9]+)*\.1\.gz")
REQUIRED_MAN = "usr/share/man/man1/epistle.1.gz"

# The files of the .deb that are always there, and where each one lands.
FIXED = {
    BINARY: (BINARY, 0o755),
    SYSCTL_DEB: (SYSCTL, 0o644),
    "usr/share/bash-completion/completions/epistle": ("usr/share/bash-completion/completions/epistle", 0o644),
    "usr/share/zsh/vendor-completions/_epistle": ("usr/share/zsh/site-functions/_epistle", 0o644),
    "usr/share/fish/vendor_completions.d/epistle.fish": ("usr/share/fish/vendor_completions.d/epistle.fish", 0o644),
    "usr/share/doc/epistle/changelog.gz": ("usr/share/doc/epistle/changelog.gz", 0o644),
    "usr/share/doc/epistle/copyright": ("usr/share/licenses/epistle/copyright", 0o644),
}
# dh_compress compresses a document once it passes a size, so each of these
# arrives under one of two names: exactly one of them.
DOCUMENTS = ("usr/share/doc/epistle/README.md", "usr/share/doc/epistle/epistle.service")

# Added from the repository: source path, destination, mode.
FROM_REPOSITORY = (
    ("LICENSE", "usr/share/licenses/epistle/LICENSE", 0o644),
    ("packaging/linux/setup.sh", "usr/lib/epistle/setup", 0o755),
    ("packaging/linux/sysusers.conf", "usr/lib/sysusers.d/epistle.conf", 0o644),
)
CONFIGURE = "usr/lib/epistle/configure"
OWN_DIRECTORIES = ("usr/lib/epistle", "usr/share/doc/epistle", "usr/share/licenses/epistle")

RECONFIGURE_RE = re.compile(r"(?:sudo )?dpkg-reconfigure epistle")
RECONFIGURE = "sudo /usr/lib/epistle/setup"


class Refused(Exception):
    pass


def read_ar(data):
    """The members of an ar archive as [(name, bytes)], in order, no duplicates."""
    if data[:8] != b"!<arch>\n":
        raise Refused("not an ar archive")
    members, pos = [], 8
    while pos < len(data):
        header = data[pos : pos + 60]
        if len(header) < 60 or header[58:60] != b"`\n":
            raise Refused("damaged ar header")
        name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as error:
            raise Refused("damaged ar size") from error
        pos += 60
        if size < 0 or pos + size > len(data):
            raise Refused("ar member runs past the end")
        members.append((name, data[pos : pos + size]))
        pos += size + (size & 1)
    names = [name for name, _ in members]
    if len(set(names)) != len(names):
        raise Refused("an ar member name appears twice")
    return members


def read_tar_xz(blob, what):
    try:
        raw = lzma.LZMADecompressor().decompress(blob, max_length=MAX_MEMBER + 1)
    except lzma.LZMAError as error:
        raise Refused(f"{what} is not xz: {error}") from error
    if len(raw) > MAX_MEMBER:
        raise Refused(f"{what} is larger than {MAX_MEMBER} bytes once decompressed")
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")


def normalise(name):
    return name.removeprefix("./").rstrip("/")


def control_member(tar, name, limit):
    members = [m for m in tar.getmembers() if normalise(m.name) == name]
    if len(members) != 1 or not members[0].isreg() or members[0].size > limit:
        raise Refused(f"control.tar.xz has no single regular `{name}` file")
    return tar.extractfile(members[0]).read()


def control_fields(text):
    fields = {}
    for line in text.splitlines():
        if line and not line[0].isspace() and ":" in line:
            key, value = line.split(":", 1)
            fields.setdefault(key, value.strip())
    return fields


def check_elf(blob, machine):
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise Refused(f"{BINARY} is not an ELF file")
    if blob[4] != 2 or blob[5] != 1:
        raise Refused(f"{BINARY} is not a 64-bit little-endian ELF")
    if int.from_bytes(blob[18:20], "little") != machine:
        raise Refused(f"{BINARY} is built for another architecture than the package")
    offset = int.from_bytes(blob[32:40], "little")
    size = int.from_bytes(blob[54:56], "little")
    count = int.from_bytes(blob[56:58], "little")
    if size < 56 or count == 0 or offset + size * count > len(blob):
        raise Refused(f"{BINARY} has a damaged program header table")
    for index in range(count):
        if int.from_bytes(blob[offset + index * size :][:4], "little") == 3:  # PT_INTERP
            raise Refused(f"{BINARY} asks for a dynamic loader; the package must carry a static binary")


def carry_over(postinst):
    """The postinst of the .deb as a script that is true on a host with no dpkg.

    It names the file of the port floor, which moved, and it tells the reader to run
    `dpkg-reconfigure epistle`, which is `setup` here. Both must be found, and no
    other mention of dpkg may be left: a change to the postinst that this does not
    understand stops the packaging instead of shipping advice that cannot work.
    """
    try:
        text = postinst.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused("the postinst is not UTF-8") from error
    if not text.startswith("#!/bin/sh\n"):
        raise Refused("the postinst is not a /bin/sh script")
    if "/" + SYSCTL_DEB not in text:
        raise Refused("the postinst no longer names the file of the port floor")
    text = text.replace("/" + SYSCTL_DEB, "/" + SYSCTL)
    text, count = RECONFIGURE_RE.subn(RECONFIGURE, text)
    if count == 0:
        raise Refused("the postinst no longer says how to run it again")
    if "dpkg" in text:
        raise Refused("the postinst mentions dpkg in a way this packaging does not carry over")
    return text.encode("utf-8")


def destination(name):
    """Where a file of the .deb lands, or None for a file this packaging does not know."""
    if name in FIXED:
        return FIXED[name]
    if MAN_RE.fullmatch(name) or name.removesuffix(".gz") in DOCUMENTS:
        return (name, 0o644)
    return None


def read_deb(path, version, arch):
    """The files of the .deb by destination, as {path: (mode, bytes)}, and the time of its binary."""
    if os.path.islink(path) or not os.path.isfile(path):
        raise Refused(f"{path} is not a regular file")
    if os.path.getsize(path) > MAX_DEB:
        raise Refused("the .deb is larger than 300 MiB")
    with open(path, "rb") as handle:
        members = read_ar(handle.read())
    names = [name for name, _ in members]
    if names != ["debian-binary", "control.tar.xz", "data.tar.xz"]:
        raise Refused(f"unexpected .deb members: {names}")
    blobs = dict(members)
    if blobs["debian-binary"] != b"2.0\n":
        raise Refused("not a format 2.0 .deb")

    control = read_tar_xz(blobs["control.tar.xz"], "control.tar.xz")
    fields = control_fields(control_member(control, "control", 65536).decode("utf-8", "replace"))
    for key, want in (("Package", "epistle"), ("Version", version), ("Architecture", arch)):
        if fields.get(key) != want:
            raise Refused(f"control says {key}: {fields.get(key)!r}, expected {want!r}")
    configure = carry_over(control_member(control, "postinst", 1024 * 1024))

    data = read_tar_xz(blobs["data.tar.xz"], "data.tar.xz")
    seen, found, epoch = set(), {}, None
    for member in data.getmembers():
        name = normalise(member.name)
        if name in ("", "."):
            continue
        if name.startswith("/") or ".." in name.split("/"):
            raise Refused(f"unsafe path in the .deb: {member.name!r}")
        if member.isdir():
            continue
        if not member.isreg():
            raise Refused(f"{member.name!r} is not a regular file or directory")
        if name in seen:
            raise Refused(f"{name} appears twice")
        seen.add(name)
        target = destination(name)
        if target is None:
            raise Refused(f"the .deb carries a file this packaging does not know: {name}")
        if member.size > MAX_MEMBER:
            raise Refused(f"{name} is too large")
        found[target[0]] = (target[1], data.extractfile(member).read())
        if name == BINARY:
            epoch = int(member.mtime)
    missing = sorted(set(FIXED) - seen)
    if REQUIRED_MAN not in seen:
        missing.append(REQUIRED_MAN)
    if missing:
        raise Refused(f"the .deb lacks: {', '.join(missing)}")
    for document in DOCUMENTS:
        held = sorted(seen & {document, document + ".gz"})
        if len(held) != 1:
            raise Refused(f"the .deb must carry {document} once, compressed or not; it carries {held}")
    check_elf(found[BINARY][1], ARCHES[arch])
    found[CONFIGURE] = (0o755, configure)
    return found, epoch


def read_repository(root):
    found = {}
    for source, target, mode in FROM_REPOSITORY:
        path = os.path.join(root, source)
        if os.path.islink(path) or not os.path.isfile(path):
            raise Refused(f"{path} is not a regular file")
        with open(path, "rb") as handle:
            blob = handle.read(65537)
        if not blob or len(blob) > 65536:
            raise Refused(f"{source} is empty or larger than 64 KiB")
        found[target] = (mode, blob)
    return found


def write(out, files, epoch):
    if os.path.lexists(out):
        raise Refused(f"{out} exists; give a new directory")
    root = os.path.join(out, "root")
    os.makedirs(root)
    directories = set()
    for path, (mode, blob) in sorted(files.items()):
        target = os.path.join(root, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "xb") as handle:
            handle.write(blob)
        os.chmod(target, mode)
        os.utime(target, (epoch, epoch))
        parent = os.path.dirname(path)
        while parent:
            directories.add(parent)
            parent = os.path.dirname(parent)
    # Deepest first, so that setting the time of a directory is the last change in it.
    for directory in sorted(directories, key=len, reverse=True):
        os.chmod(os.path.join(root, directory), 0o755)
        os.utime(os.path.join(root, directory), (epoch, epoch))
    os.chmod(root, 0o755)
    os.utime(root, (epoch, epoch))

    with open(os.path.join(out, "files.txt"), "w", encoding="ascii") as listing:
        for path, (mode, blob) in sorted(files.items()):
            listing.write(f"{mode:04o} {path} {hashlib.sha256(blob).hexdigest()} {len(blob)}\n")
    own = sorted(d for d in directories if any(d == o or d.startswith(o + "/") for o in OWN_DIRECTORIES))
    with open(os.path.join(out, "dirs.txt"), "w", encoding="ascii") as listing:
        listing.writelines(f"{directory}\n" for directory in own)
    with open(os.path.join(out, "epoch"), "w", encoding="ascii") as handle:
        handle.write(f"{epoch}\n")


def stage(deb, version, arch, repository, out):
    """Stage one .deb into `out`; returns the number of files."""
    if not VERSION_RE.fullmatch(version):
        raise Refused(f"version {version!r} is not X.Y.Z")
    if arch not in ARCHES:
        raise Refused(f"unknown architecture {arch!r}")
    files, epoch = read_deb(deb, version, arch)
    files.update(read_repository(repository))
    write(out, files, epoch)
    return len(files)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for option in ("--deb", "--version", "--arch", "--repository", "--out"):
        parser.add_argument(option, required=True)
    args = parser.parse_args(argv)
    try:
        count = stage(args.deb, args.version, args.arch, args.repository, args.out)
    except (Refused, OSError, tarfile.TarError) as error:
        print(f"stage-payload: {error}", file=sys.stderr)
        return 1
    print(f"staged {count} files for epistle {args.version} ({args.arch})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
