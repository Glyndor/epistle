#!/usr/bin/env bash
#
# Runs INSIDE the container admission.sh starts (an rpm that knows RPMFORMAT).
# Reads: /channel (the checkout of the channel), /release (the two packages).
# Env:   VERSION
set -Eeuo pipefail
trap 'echo "failed in the container script at line $LINENO: $BASH_COMMAND" >&2' ERR

: "${VERSION:?}"
dnf -y --setopt=install_weak_deps=0 install python3-cryptography cpio diffutils findutils gawk \
	>/tmp/dnf.log 2>&1 || { cat /tmp/dnf.log >&2; exit 1; }

mkdir /tmp/keyring /tmp/signed
cp /release/*.rpm /tmp/signed/
# One throwaway key: its public half is the channel's trust for this run only.
python3 -I - <<'PY'
import base64
import pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

key = Ed25519PrivateKey.generate()
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
pathlib.Path("/tmp/keyring/glyndor-release-ed25519.b64").write_text(base64.b64encode(public).decode() + "\n")
for package in sorted(pathlib.Path("/tmp/signed").glob("*.rpm")):
    pathlib.Path(f"{package}.sig").write_bytes(key.sign(package.read_bytes()))
PY
echo '# no second key in this run' >/tmp/keyring/glyndor-release-mldsa65.b64
echo '# no product requires the second signature' >/tmp/keyring/pq-required-products

admit() { bash /channel/scripts/verify/admit-release.sh --keyring /tmp/keyring epistle "v$VERSION" "$1"; }
refused() { # <directory> <reason the channel gives>
	if admit "$1" >/tmp/refusal.log 2>&1; then
		echo "the channel admitted $1" >&2
		exit 1
	fi
	grep -F -- "$2" /tmp/refusal.log || { cat /tmp/refusal.log >&2; echo "refused for another reason than '$2'" >&2; exit 1; }
}

admit /tmp/signed

cp -r /tmp/signed /tmp/tampered
for package in /tmp/tampered/*x86_64.rpm; do printf 'x' >>"$package"; done
refused /tmp/tampered 'invalid signature'

cp -r /tmp/signed /tmp/short
rm /tmp/short/*aarch64.rpm /tmp/short/*aarch64.rpm.sig
refused /tmp/short 'and the contract names 2'

cp -r /tmp/signed /tmp/extra
echo x >/tmp/extra/epistle.txt
refused /tmp/extra 'the contract does not name'
