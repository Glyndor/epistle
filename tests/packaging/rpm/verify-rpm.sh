#!/usr/bin/env bash
#
# What the rpm channel reads and what a user sees, for one built package.
#
#   verify-rpm.sh RPM STAGE_DIR VERSION RPM_ARCH [UPGRADE_RPM]
#
# 1. The header of the channel's contract, Provides, Requires, no relation that
#    acts on another package, no scriptlet and no trigger, nothing under /etc,
#    and the files with their modes and owners.
# 2. For x86_64 only (the binary cannot run elsewhere without an emulator):
#    install-in-container.sh in AlmaLinux 9, the oldest distribution the channel
#    serves, and in Fedora, whose rpm is the newest, with UPGRADE_RPM as the later
#    version.
#
# Needs podman (or CONTAINER_ENGINE). The install steps need the network, to take
# systemd and the tools setup uses from the distribution.
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd)"
rpm="${1:?rpm}"
stage="${2:?stage dir}"
version="${3:?version}"
arch="${4:?arch}"
upgrade="${5:-}"
engine="${CONTAINER_ENGINE:-podman}"
# shellcheck disable=SC1091 # a sibling file, not followed by the lint
. "$here/../../../.github/scripts/distro_packages/images.env"

fail() { echo "verify-rpm: $*" >&2; exit 1; }

name="epistle-${version}-1.glyndor.any.${arch}.rpm"
[ "$(basename "$rpm")" = "$name" ] || fail "the file is named $(basename "$rpm"), expected $name"
if [ ! -f "$rpm" ] || [ -L "$rpm" ]; then fail "$rpm is not a regular file"; fi
[ "$(stat -c %s "$rpm")" -le $((300 * 1024 * 1024)) ] || fail "$name is over 300 MiB"
rpm_dir="$(cd "$(dirname "$rpm")" && pwd)"
stage="$(cd "$stage" && pwd)"

query() { # image args...
	local image="$1"
	shift
	"$engine" run --rm --network none --volume "$rpm_dir:/pkg:ro" "$image" rpm "$@" "/pkg/$name"
}

# --- 1. the header -----------------------------------------------------------
want="epistle|${version}|1.glyndor.any|(none)|${arch}|Glyndor|Glyndor <noreply@glyndor.net>|4"
got="$(query "$RPM_QUERY_IMAGE" -qp --qf '%{NAME}|%{VERSION}|%{RELEASE}|%{EPOCH}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{RPMFORMAT}\n')"
[ "$got" = "$want" ] || fail "header fields differ:
  want $want
  got  $got"
echo "ok    header fields"

got_old="$(query "$RPM_BUILD_BASE" -qp --qf '%{NAME}|%{VERSION}|%{RELEASE}|%{EPOCH}|%{ARCH}|%{VENDOR}|%{PACKAGER}\n')"
[ "$got_old" = "${want%|4}" ] || fail "rpm 4.16 reads other fields: $got_old"
echo "ok    rpm 4.16 reads it"

isa="epistle(x86-64)"
[ "$arch" = aarch64 ] && isa="epistle(aarch-64)"
provides="$(query "$RPM_QUERY_IMAGE" -qp --provides | sed 's/ = .*//' | sort | paste -sd' ')"
[ "$provides" = "epistle $isa" ] || fail "Provides: $provides"
requires="$(query "$RPM_QUERY_IMAGE" -qp --requires | grep -v '^rpmlib(' | sort | paste -sd'|')"
[ "$requires" = "podman >= 6.2.0|podup >= 6.0.0|systemd" ] || fail "Requires besides rpmlib: $requires"
relations="$(query "$RPM_QUERY_IMAGE" -qp --obsoletes --conflicts --recommends --suggests --supplements --enhances)"
[ -z "$relations" ] || [ "$relations" = "(none)" ] || fail "relations the channel refuses: $relations"
scripts="$(query "$RPM_QUERY_IMAGE" -qp --scripts --triggers --filetriggers)"
[ -z "$scripts" ] || fail "the package carries a scriptlet or a trigger: $scripts"
echo "ok    provides, requires, no other relation, no scriptlet"

entries="$(query "$RPM_QUERY_IMAGE" -qp --qf '[%{FILEMODES:octal} %{FILENAMES} %{FILEUSERNAME} %{FILEGROUPNAME}\n]')"
files="$(grep '^100' <<<"$entries" | sort -k2)"
expected="$(awk '{ printf "100%s /%s root root\n", substr($1, 2), $2 }' "$stage/files.txt" | sort -k2)"
[ "$files" = "$expected" ] || fail "the files in the package are not the staged ones:
$(diff <(echo "$expected") <(echo "$files") || true)"
dirs="$(grep -v '^100' <<<"$entries" | sort -k2)"
expected_dirs="$(awk '{ printf "40755 /%s root root\n", $1 }' "$stage/dirs.txt" | sort -k2)"
[ "$dirs" = "$expected_dirs" ] || fail "directories the package owns: $dirs"
if awk '{ print $2 }' <<<"$entries" | grep -E '^/(etc|var)(/|$)'; then
	fail "the package ships something under /etc or /var, which an upgrade could overwrite"
fi
echo "ok    file list, modes and owners; nothing under /etc or /var"

if [ "$arch" != x86_64 ]; then
	echo "skip  install and run: the $arch binary needs an emulator"
	exit 0
fi

# --- 2. install, setup, upgrade, removal -------------------------------------
[ -n "$upgrade" ] || fail "an x86_64 check needs the package of a later version to upgrade to"
[ -f "$upgrade" ] || fail "$upgrade is not a file"
upgrade_dir="$(cd "$(dirname "$upgrade")" && pwd)"

for image in "$RPM_BUILD_BASE" "$RPM_QUERY_IMAGE"; do
	"$engine" run --rm \
		--volume "$rpm_dir:/pkg:ro" --volume "$upgrade_dir:/upgrade:ro" --volume "$stage:/stage:ro" \
		--volume "$here/install-in-container.sh:/work/install.sh:ro" \
		--volume "$here/../host/lifecycle.sh:/work/lifecycle.sh:ro" \
		--env "VERSION=$version" --env "NAME=$name" --env "UPGRADE=$(basename "$upgrade")" \
		--env "NEXT_VERSION=$(basename "$upgrade" | cut -d- -f2)" \
		"$image" bash /work/install.sh
	echo "ok    install, setup, upgrade and removal in ${image%@*}"
done
