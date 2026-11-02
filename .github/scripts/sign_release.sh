#!/usr/bin/env bash
# Sign the release files in a directory with the Ed25519 key in the environment.
#
# Usage: sign_release.sh <dist-dir> <tag>
#
# The key comes from GLYNDOR_RELEASE_ED25519_KEY, never from the command line.
# The signing dependencies go into an isolated virtualenv from the hash-pinned
# requirements, so a system-managed cryptography cannot change what is trusted.
# Each .deb gets its own detached signature: the apt archive verifies every
# package against <deb>.sig before admitting it, and refuses to re-sign with
# its own GPG key anything it did not verify first.
set -euo pipefail

dist=${1:?usage: sign_release.sh <dist-dir> <tag>}
tag=${2:?usage: sign_release.sh <dist-dir> <tag>}
here=$(cd "$(dirname "$0")" && pwd)

if [ -z "${GLYNDOR_RELEASE_ED25519_KEY:-}" ]; then
	echo "::error::no signing key in the environment; refusing to release unsigned artifacts." >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -m venv "$work/venv"
py="$work/venv/bin/python"
"$py" -m pip install --quiet --require-hashes -r "$here/sign-requirements.txt"

"$py" "$here/sign.py" "$dist/epistle-${tag}-x86_64-linux"
for deb in "$dist"/epistle_*.deb; do
	"$py" "$here/sign.py" "$deb"
done
"$py" "$here/sign.py" "$dist/SHA256SUMS"
