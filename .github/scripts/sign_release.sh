#!/usr/bin/env bash
# Sign the release files in a directory with the Ed25519 key in the environment.
#
# Usage: sign_release.sh <venv-dir> <dist-dir> <tag>
#
# The key comes from GLYNDOR_RELEASE_ED25519_KEY, never from the command line.
# The virtualenv was made by release/prepare_signing_venv.sh in an earlier step,
# from the hash-pinned requirements and with no key around: nothing is installed
# here, and no Python runs in the directory that holds the files. The directory
# has to hold exactly the files of this tag (see release/release_files.py), as
# regular files, and that is checked before the key is read. Each file gets a
# detached signature, by explicit path: the apt archive verifies every package
# against <deb>.sig before admitting it, and refuses to re-sign with its own GPG
# key anything it did not verify first.
set -euo pipefail

venv=${1:?usage: sign_release.sh <venv-dir> <dist-dir> <tag>}
dist=${2:?usage: sign_release.sh <venv-dir> <dist-dir> <tag>}
tag=${3:?usage: sign_release.sh <venv-dir> <dist-dir> <tag>}
here=$(cd "$(dirname "$0")" && pwd)

if [ -z "${GLYNDOR_RELEASE_ED25519_KEY:-}" ]; then
	echo "::error::no signing key in the environment; refusing to release unsigned artifacts." >&2
	exit 1
fi

# Before the key is used: nothing but the files this tag has.
python3 -I "$here/release/release_files.py" check "$dist" "$tag" built >&2

# From a directory of its own, so that nothing in the files can be imported.
cd "$here"
mapfile -t files < <(python3 -I "$here/release/release_files.py" names "$tag" built)
for name in "${files[@]}"; do
	"$venv/bin/python" -I "$here/sign.py" "$dist/$name"
done
