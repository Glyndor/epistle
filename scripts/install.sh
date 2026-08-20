#!/usr/bin/env bash
# Install the latest epistle release binary.
#
# Usage: ./install.sh [version]
#   version: tag like v0.1.0; defaults to the latest release.
#
# Shebang is bash (not POSIX sh) on purpose: the two-key rotation contract
# (EPISTLE_RELEASE_PUBKEY_B64 / _PUBKEY2_B64) is a bash array, and rebuilding
# it in pure sh would need a key-counter workaround for the same logic. bash
# is universally available on the Linux server this script targets.
set -euo pipefail

REPO="Glyndor/epistle"
ARCH="x86_64-linux"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

fail() {
	echo "error: $1" >&2
	exit 1
}

version="${1:-}"
if [ -z "$version" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -n 1 | cut -d '"' -f 4) \
		|| fail "cannot determine the latest release"
fi
[ -n "$version" ] || fail "cannot determine the latest release"

base="https://github.com/${REPO}/releases/download/${version}"
binary="epistle-${version}-${ARCH}"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# Baked-in base64 (unpadded) raw Ed25519 public key (32 bytes), the public half
# of the one org signing secret GLYNDOR_RELEASE_ED25519_KEY that release.yml
# signs with.
#
# Slot 2 is empty and stays empty outside a rotation. Rotations are two-phase:
# a transition release carries both keys and is still signed with the old one,
# so installs that only trust the old key can adopt it; the release after that
# is signed with the new key and clears the old slot. A blank slot is skipped,
# and the signature passes if any populated slot validates.
#
# Override for a fork via EPISTLE_RELEASE_PUBKEY_B64 / _PUBKEY2_B64.
#
# Releases before v0.3.5 were signed with the key that was retired in July 2026
# and whose private half is gone, so this key will not verify them - that is
# correct behaviour, not a bug to work around.
EPISTLE_RELEASE_PUBKEY_B64="${EPISTLE_RELEASE_PUBKEY_B64:-HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM}"
EPISTLE_RELEASE_PUBKEY2_B64="${EPISTLE_RELEASE_PUBKEY2_B64:-}"

PUBKEYS=()
[[ -n "$EPISTLE_RELEASE_PUBKEY_B64" ]]  && PUBKEYS+=("$EPISTLE_RELEASE_PUBKEY_B64")
[[ -n "$EPISTLE_RELEASE_PUBKEY2_B64" ]] && PUBKEYS+=("$EPISTLE_RELEASE_PUBKEY2_B64")

# Verify the Ed25519 signature over SHA256SUMS.
#   ed25519_verify <sig-file> <data-file>
# Exit: 0 verified, 1 signature present but INVALID (tampered or wrong key),
#       2 cannot verify (no python3 / 'cryptography' / no key configured).
ed25519_verify() {
	[[ ${#PUBKEYS[@]} -gt 0 ]] || return 2
	command -v python3 >/dev/null 2>&1 || return 2
	python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null || return 2
	python3 - "$1" "$2" "${PUBKEYS[@]}" <<'PYEOF'
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sig_file, data_file = sys.argv[1], sys.argv[2]
sig = open(sig_file, "rb").read()
data = open(data_file, "rb").read()
for slot, pubkey_b64 in enumerate(sys.argv[3:]):
    try:
        # Pad to a 4-byte boundary the way sign.py does: the installer stores
        # the key unpadded, and a stricter decoder would reject a fixed two-"="
        # suffix when the key is already a multiple of four chars long.
        raw = base64.b64decode(pubkey_b64 + "=" * (-len(pubkey_b64) % 4))
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, data)
        sys.exit(0)
    except InvalidSignature:
        continue
sys.exit(1)
PYEOF
	case $? in
		0) return 0 ;;
		*) return 1 ;;
	esac
}

# Fetch the signed manifest and verify it BEFORE downloading the payload.
# A release whose manifest is signed with an unknown key, or whose signature
# cannot be verified at all, must abort before any binary hits disk: TLS is
# not the trust anchor, the signature is.
echo "Downloading manifest and signature ..."
curl -fsSL -o "${workdir}/SHA256SUMS"     "${base}/SHA256SUMS"     || fail "cannot download SHA256SUMS"
curl -fsSL -o "${workdir}/SHA256SUMS.sig" "${base}/SHA256SUMS.sig" || fail "cannot download SHA256SUMS.sig"

echo "Verifying SHA256SUMS signature ..."
rc=0
ed25519_verify "${workdir}/SHA256SUMS.sig" "${workdir}/SHA256SUMS" || rc=$?
case "$rc" in
	0) ;;
	1) fail "SHA256SUMS signature verification failed - release may be tampered" ;;
	2) fail "cannot verify SHA256SUMS signature: install python3 with the 'cryptography' package and ensure the release key is configured" ;;
	*) fail "SHA256SUMS signature verification exited unexpectedly (rc=$rc)" ;;
esac

echo "Downloading ${binary} ..."
curl -fsSL -o "${workdir}/${binary}" "${base}/${binary}" || fail "cannot download ${binary}"

echo "Verifying checksum ..."
(cd "$workdir" && grep " ${binary}\$" SHA256SUMS | sha256sum -c -) || fail "checksum verification failed for ${binary}"

echo "Installing to ${INSTALL_DIR}/epistle ..."
install -m 0755 "${workdir}/${binary}" "${INSTALL_DIR}/epistle" || fail "cannot install to ${INSTALL_DIR}"

echo "Installed: $("${INSTALL_DIR}/epistle" --version)"