#!/usr/bin/env bash
#
# What the pacman channel reads and what a user sees, for one built package.
#
#   verify-pacman.sh PKG STAGE_DIR VERSION UPGRADE_PKG
#
# 1. The members and the .PKGINFO fields of the channel's contract, with no
#    scriptlet and nothing under /etc or /var (no network).
# 2. install-in-container.sh in Arch Linux, with UPGRADE_PKG as the later version.
#
# Needs podman (or CONTAINER_ENGINE). The install step needs the network: a full
# upgrade first, since the pinned image is older than the repositories, and the
# dependencies Arch carries.
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd)"
pkg="${1:?package}"
stage="${2:?stage dir}"
version="${3:?version}"
upgrade="${4:?package of a later version}"
engine="${CONTAINER_ENGINE:-podman}"
# shellcheck disable=SC1091 # a sibling file, not followed by the lint
. "$here/../../../.github/scripts/distro_packages/images.env"

fail() { echo "verify-pacman: $*" >&2; exit 1; }

name="epistle-${version}-1-x86_64.pkg.tar.zst"
[ "$(basename "$pkg")" = "$name" ] || fail "the file is named $(basename "$pkg"), expected $name"
if [ ! -f "$pkg" ] || [ -L "$pkg" ]; then fail "$pkg is not a regular file"; fi
[ -f "$upgrade" ] || fail "$upgrade is not a file"
[ "$(stat -c %s "$pkg")" -le $((300 * 1024 * 1024)) ] || fail "$name is over 300 MiB"
pkg_dir="$(cd "$(dirname "$pkg")" && pwd)"
upgrade_dir="$(cd "$(dirname "$upgrade")" && pwd)"
stage="$(cd "$stage" && pwd)"

# --- 1. members and .PKGINFO -------------------------------------------------
# The script below is for the container's shell, not this one.
# shellcheck disable=SC2016
"$engine" run --rm --network none \
	--volume "$pkg_dir:/pkg:ro" --volume "$stage:/stage:ro" \
	--env "VERSION=$version" --env "NAME=$name" \
	"$PACMAN_BUILD_BASE" bash -Eeuo pipefail -c '
	export LC_ALL=C
	trap "echo \"failed in the container script at line \$LINENO: \$BASH_COMMAND\" >&2" ERR
	refuse() { echo "refused: $1" >&2; exit 1; }
	members="$(bsdtar -tf "/pkg/$NAME")"
	test "$(grep -c "^\.PKGINFO$" <<<"$members")" = 1
	# Of the entries with a dot at the root, these and no scriptlet.
	test "$(grep "^\." <<<"$members" | sort | paste -sd" ")" = ".BUILDINFO .MTREE .PKGINFO"
	if grep -E "^/|(^|/)\.\.(/|$)" <<<"$members"; then refuse "a member name leaves the package root"; fi
	if grep -E "^(etc|var)(/|$)" <<<"$members"; then refuse "a file under /etc or /var, which an upgrade could overwrite"; fi
	listing="$(bsdtar --numeric-owner -tvf "/pkg/$NAME")"
	if grep -E "^[^-d]" <<<"$listing"; then refuse "a member is neither a file nor a directory"; fi
	if awk "\$3 != 0 || \$4 != 0" <<<"$listing" | grep .; then refuse "a member does not belong to root"; fi
	# The files are the staged ones, with their modes.
	files="$(awk "/^-/ && \$NF !~ /^\\./ { print \$1, \$NF }" <<<"$listing" | sort -k2)"
	expected="$(awk "{ mode = \$1 == \"0755\" ? \"-rwxr-xr-x\" : \"-rw-r--r--\"; print mode, \$2 }" /stage/files.txt | sort -k2)"
	test "$files" = "$expected" || { diff <(echo "$expected") <(echo "$files") >&2 || true; refuse "the files are not the staged ones"; }
	info="$(bsdtar -xOf "/pkg/$NAME" .PKGINFO)"
	field() { sed -n "s/^$1 = //p" <<<"$info"; }
	test "$(field pkgname)" = epistle
	test "$(field pkgbase)" = epistle
	test "$(field pkgver)" = "$VERSION-1"
	test "$(field arch)" = x86_64
	test "$(field packager)" = "Glyndor <noreply@glyndor.net>"
	for key in replaces conflict provides backup group; do test -z "$(field "$key")"; done
	test "$(field depend | paste -sd" ")" = "podman>=6.2.0 podup>=6.0.0 wireguard-tools systemd shadow"
'
echo "ok    members, owners, modes and .PKGINFO fields"

# --- 2. install, setup, upgrade, removal -------------------------------------
"$engine" run --rm \
	--volume "$pkg_dir:/pkg:ro" --volume "$upgrade_dir:/upgrade:ro" --volume "$stage:/stage:ro" \
	--volume "$here/install-in-container.sh:/work/install.sh:ro" \
	--volume "$here/../host/lifecycle.sh:/work/lifecycle.sh:ro" \
	--env "VERSION=$version" --env "NAME=$name" --env "UPGRADE=$(basename "$upgrade")" \
	--env "NEXT_VERSION=$(basename "$upgrade" | cut -d- -f2)" \
	"$PACMAN_BUILD_BASE" bash /work/install.sh
echo "ok    install, setup, upgrade and removal in Arch Linux"
