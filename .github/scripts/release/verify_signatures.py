#!/usr/bin/env python3
"""Check every release signature against the public key the release is meant to have.

A signature is only worth publishing if it verifies under the key people were
given, and that key has to be pinned apart from the secret that signs: a secret
that holds some other valid seed, by a mistake or a substitution, makes signatures
that are well formed, non-empty and useless. The pinned key is the file
`.github/release/ed25519-public-key.b64` of the verified commit (the raw 32 bytes,
base64, the same line the apt archive trusts).

Run it with the signing virtualenv's python in isolated mode, from a directory of
its own:  python -I verify_signatures.py <dist-dir> <tag> <public-key-file>
It prints one `error:` line per problem and exits 1.
"""

import base64
import binascii
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_files  # noqa: E402


def load_key(path):
    text = Path(path).read_text().strip()
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if len(lines) != 1:
        raise ValueError("the key file must hold exactly one key")
    raw = lines[0].strip()
    try:
        data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f"the key is not base64: {err}") from err
    if len(data) != 32:
        raise ValueError(f"the key is {len(data)} bytes, not 32")
    return Ed25519PublicKey.from_public_bytes(data)


def verify(directory, tag, key_file):
    problems = release_files.check(directory, tag, "signed")
    if problems:
        return problems
    key = load_key(key_file)
    root = Path(directory)
    for name in release_files.built_names(tag):
        try:
            key.verify((root / f"{name}.sig").read_bytes(), (root / name).read_bytes())
        except InvalidSignature:
            problems.append(f"{name}.sig does not verify under the pinned release key")
    return problems


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems = verify(argv[1], argv[2], argv[3])
    except (ValueError, OSError) as err:
        problems = [str(err)]
    for problem in problems:
        print(f"error: {problem}")
    if not problems:
        print(f"every signature of {argv[2]} verifies under the pinned release key")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
