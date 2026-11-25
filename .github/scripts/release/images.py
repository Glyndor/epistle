#!/usr/bin/env python3
"""The decisions of the image part of a release, by digest and never by tag.

An image tag is a name somebody with write access to the registry can move, so
nothing here trusts one:

  decide   whether an architecture's image has to be built: refuses to replace a
           tag that already exists, and with images-only accepts one only if its
           revision label is the verified commit, then reuses it by digest.
  digest   checks the shape of a digest handed from a builder to the assembler.
  list     checks that a manifest list holds exactly the digests the builders
           produced, one per architecture.
  promote  which of the tags people consume this version may move: the exact one
           if it is free or already points at this digest, the floating
           `<major>.<minor>` and `<major>` only if no higher stable version of the
           same line exists, so recovering an old version never moves them back.

Standard library only; skopeo is the registry client and is called with fixed
arguments.

Usage:
  images.py decide <image> <tag> <commit> <images-only: true|false>
  images.py digest <value>
  images.py list <manifest.json> <amd64-digest> <arm64-digest>
  images.py promote <image> <version> <digest>   (prints one tag per line)
"""

import json
import re
import subprocess
import sys

REVISION = "org.opencontainers.image.revision"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
STABLE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+$")


class Refusal(Exception):
    pass


def skopeo(*args):
    """The registry client. A missing image is exit status 1 with a message; anything else is an error."""
    done = subprocess.run(["skopeo", *args], capture_output=True, text=True, check=False)
    return done


def exists(reference):
    done = skopeo("inspect", "--raw", f"docker://{reference}")
    if done.returncode == 0:
        return True
    text = done.stderr.lower()
    if "manifest unknown" in text or "name unknown" in text or "not found" in text or "404" in text:
        return False
    raise Refusal(f"could not tell whether {reference} exists: {done.stderr.strip()[:200]}")


def inspect(reference):
    done = skopeo("inspect", f"docker://{reference}")
    if done.returncode != 0:
        raise Refusal(f"could not read {reference}: {done.stderr.strip()[:200]}")
    info = json.loads(done.stdout)
    raw = skopeo("inspect", "--raw", f"docker://{reference}")
    return info, raw.stdout


def decide(image, tag, commit, images_only):
    if not IMAGE.match(image) or not re.match(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$", tag):
        raise Refusal("the image or the tag has characters a registry name does not")
    if not COMMIT.match(commit):
        raise Refusal("the commit is not a full SHA-1")
    reference = f"{image}:{tag}"
    if not exists(reference):
        return "build", ""
    if not images_only:
        raise Refusal(f"{reference} is already published; an image is never replaced, cut a new version")
    info, _ = inspect(reference)
    revision = (info.get("Labels") or {}).get(REVISION)
    if revision != commit:
        raise Refusal(f"{reference} was built from {revision!r}, not from the verified commit {commit}; it is not replaced")
    digest = info.get("Digest", "")
    if not DIGEST.match(digest):
        raise Refusal(f"{reference} has no usable digest")
    return "reuse", digest


def check_digest(value):
    if not DIGEST.match(value):
        raise Refusal(f"{value!r} is not a sha256 digest")
    return value


def check_list(document, amd64, arm64):
    check_digest(amd64)
    check_digest(arm64)
    manifest = json.loads(document)
    held = sorted((m["platform"]["architecture"], m["digest"]) for m in manifest.get("manifests", []))
    expected = sorted([("amd64", amd64), ("arm64", arm64)])
    if held != expected:
        raise Refusal(f"the manifest list holds {held}, not {expected}")
    return True


def tags_of(image):
    done = skopeo("list-tags", f"docker://{image}")
    if done.returncode != 0:
        raise Refusal(f"could not list the tags of {image}: {done.stderr.strip()[:200]}")
    return json.loads(done.stdout).get("Tags", [])


def highest(versions, within):
    found = [tuple(int(p) for p in v.split(".")) for v in versions if STABLE.match(v)]
    found = [v for v in found if v[: len(within)] == within]
    return max(found) if found else None


def promote_tags(version, existing, exact_exists_with_other_digest=False):
    """The tags this version may move, given the exact tags the registry holds."""
    if exact_exists_with_other_digest:
        raise Refusal(f"{version} already names another image")
    match = STABLE.match(version)
    if not match:
        return [version]  # a prerelease: its exact tag and nothing floating
    major, minor, patch = (int(p) for p in match.groups())
    tags = [version]
    pool = list(existing) + [version]
    if highest(pool, (major, minor)) == (major, minor, patch):
        tags.append(f"{major}.{minor}")
    if highest(pool, (major,)) == (major, minor, patch):
        tags.append(str(major))
    return tags


def promote(image, version, digest):
    check_digest(digest)
    reference = f"{image}:{version}"
    other = False
    if exists(reference):
        info, _ = inspect(reference)
        other = info.get("Digest") != digest
    return promote_tags(version, tags_of(image), other)


def main(argv):
    try:
        if argv[1:2] == ["decide"] and len(argv) == 6:
            if argv[5] not in ("true", "false"):
                raise Refusal("images-only is neither true nor false")
            action, digest = decide(argv[2], argv[3], argv[4], argv[5] == "true")
            print(f"action={action}")
            print(f"digest={digest}")
            return 0
        if argv[1:2] == ["digest"] and len(argv) == 3:
            print(check_digest(argv[2]))
            return 0
        if argv[1:2] == ["list"] and len(argv) == 5:
            with open(argv[2]) as handle:
                check_list(handle.read(), argv[3], argv[4])
            return 0
        if argv[1:2] == ["promote"] and len(argv) == 5:
            print("\n".join(promote(argv[2], argv[3], argv[4])))
            return 0
    except (Refusal, ValueError, KeyError, OSError) as err:
        print(f"::error::{err}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
