#!/usr/bin/env bash
# Make the virtualenv the signer runs in, from the hash-pinned requirements.
#
# Usage: prepare_signing_venv.sh <venv-dir>
#
# It runs in a step of its own, before the key exists in any environment and
# away from the files being signed: installing a package runs code, and that
# code must never share a process, a directory or an environment with the key
# or with an artifact. The requirements are read with --require-hashes, so what
# is installed is exactly what the file names.
set -euo pipefail

venv=${1:?usage: prepare_signing_venv.sh <venv-dir>}
here=$(cd "$(dirname "$0")" && pwd)

if [ -n "${GLYNDOR_RELEASE_ED25519_KEY:-}" ]; then
	echo "::error::the signing key is in the environment of the step that installs packages." >&2
	exit 1
fi
if [ -e "$venv" ]; then
	echo "::error::$venv already exists; the environment is made fresh." >&2
	exit 1
fi

python3 -I -m venv "$venv"
"$venv/bin/python" -I -m pip install --quiet --require-hashes -r "$here/../sign-requirements.txt"
