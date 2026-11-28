#!/usr/bin/env bash
#
# The admission of the pacman channel, run over the package built here.
#
#   admission.sh PKG VERSION
#
# The channel stops its whole publication for one package it does not admit, and a
# release is immutable, so what it would say is asked before: its own
# scripts/admit/admit.py with its own products, paths and scriptlet lists, checked
# out at the commit images.env pins. The package is signed with a key made for
# this run. A tampered package and a release with a package nobody declared must
# each be refused, so a check that stopped checking shows.
#
# Needs git, zstd, python3, docker or podman (the channel reads the archive with
# the bsdtar of Arch) and the network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
pkg="${1:?package}"
version="${2:?version}"
# shellcheck disable=SC1091 # a sibling file, not followed by the lint
. "$repo/.github/scripts/distro_packages/images.env"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/release" "$work/channel"
cp -- "$pkg" "$work/release/"
name="$(basename "$pkg")"
git -C "$work/channel" init --quiet
git -C "$work/channel" fetch --quiet --depth 1 https://github.com/Glyndor/pacman "$PACMAN_CHANNEL_COMMIT"
git -C "$work/channel" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$work/channel" rev-parse HEAD)" = "$PACMAN_CHANNEL_COMMIT"
# The hash-pinned requirements the release signs with, in a fresh environment.
bash "$repo/.github/scripts/release/prepare_signing_venv.sh" "$work/venv"
python="$work/venv/bin/python"

# One throwaway key: its public half is the channel's trust for this run only.
"$python" -I - "$work" "$name" <<'PY'
import base64
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

work, name = pathlib.Path(sys.argv[1]), sys.argv[2]
key = Ed25519PrivateKey.generate()
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
(work / "key.b64").write_text(base64.b64encode(public).decode() + "\n")
(work / "pq-required").write_text("# no package requires the second signature\n")
package = work / "release" / name
(work / "release" / f"{name}.sig").write_bytes(key.sign(package.read_bytes()))
PY

assets() { # <directory> <file>: the listing `gh release view --json assets` gives
	"$python" -I -c 'import json, os, sys
d = sys.argv[1]
print(json.dumps({"assets": [{"name": n, "size": os.path.getsize(os.path.join(d, n))} for n in sorted(os.listdir(d))]}))' "$1" >"$2"
}
admit() { # <directory>
	rm -f "$work/manifest" "$work/manifest.pkginfo.json"
	assets "$1" "$work/assets.json"
	"$python" -I "$work/channel/scripts/admit/admit.py" check \
		--products "$work/channel/scripts/admit/products.txt" --repo epistle --tag "v$version" \
		--assets "$work/assets.json" --dir "$1" --ed25519-keys "$work/key.b64" \
		--pq-required "$work/pq-required" --out "$work/manifest"
}
refused() { # <directory> <reason the channel gives>
	if admit "$1" >"$work/refusal.log" 2>&1; then
		echo "the channel admitted $1" >&2
		exit 1
	fi
	grep -qF -- "$2" "$work/refusal.log" || { cat "$work/refusal.log" >&2; echo "refused for another reason than '$2'" >&2; exit 1; }
	# Without the marker of an error: printed as it is, an expected refusal would
	# annotate a green run as a failed one.
	grep -F -- "$2" "$work/refusal.log" | sed 's/::error:://; s/^/ok    refused as expected: /'
}

admit "$work/release"

cp -r "$work/release" "$work/tampered"
# Same size, one byte changed.
"$python" -I -c 'import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[-1] ^= 1
open(sys.argv[1], "wb").write(data)' "$work/tampered/$name"
refused "$work/tampered" 'is not signed by the release key'

cp -r "$work/release" "$work/extra"
echo x >"$work/extra/epistle-9.9.9-1-x86_64.pkg.tar.zst"
refused "$work/extra" 'which is not in the set derived'
echo "ok    the pacman channel admits the release at $PACMAN_CHANNEL_COMMIT"
