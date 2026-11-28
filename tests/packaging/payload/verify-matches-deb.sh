#!/usr/bin/env bash
#
# The staged payload the other packages are made from carries what the .deb
# carries: the same bytes at the same paths, with the port floor and the zsh
# completion moved, the copyright file next to the repository LICENSE, the
# postinst shipped as `configure` with its two Debian mentions rewritten, the two
# files of packaging/linux/ added, and nothing else.
#
#   verify-matches-deb.sh DEB STAGE_DIR
#
# Reads the .deb with dpkg-deb, not with the code under test.
set -euo pipefail
export LC_ALL=C

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
deb="${1:?deb}"
stage="${2:?stage dir}"

fail() { echo "verify-matches-deb: $*" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dpkg-deb -x "$deb" "$tmp/deb"
dpkg-deb -e "$deb" "$tmp/control"
sed -e 's#/usr/lib/sysctl\.d/30-glyndor-epistle\.conf#/usr/lib/epistle/sysctl.d/30-glyndor-epistle.conf#g' \
	-e 's#\(sudo \)\{0,1\}dpkg-reconfigure epistle#sudo /usr/lib/epistle/setup#g' \
	"$tmp/control/postinst" >"$tmp/configure"

sum() { sha256sum "$1" | cut -d' ' -f1; }
{
	(
		cd "$tmp/deb"
		find . -type f -printf '%P\n' | while read -r path; do
			case "$path" in
				usr/share/zsh/vendor-completions/_epistle) dest=usr/share/zsh/site-functions/_epistle ;;
				usr/lib/sysctl.d/30-glyndor-epistle.conf) dest=usr/lib/epistle/sysctl.d/30-glyndor-epistle.conf ;;
				usr/share/doc/epistle/copyright) dest=usr/share/licenses/epistle/copyright ;;
				*) dest="$path" ;;
			esac
			printf '%s %s\n' "$dest" "$(sum "$path")"
		done
	)
	printf 'usr/lib/epistle/configure %s\n' "$(sum "$tmp/configure")"
	printf 'usr/lib/epistle/setup %s\n' "$(sum "$repo/packaging/linux/setup.sh")"
	printf 'usr/lib/sysusers.d/epistle.conf %s\n' "$(sum "$repo/packaging/linux/sysusers.conf")"
	printf 'usr/share/licenses/epistle/LICENSE %s\n' "$(sum "$repo/LICENSE")"
} | sort >"$tmp/from-deb"

awk '{ print $2, $3 }' "$stage/files.txt" | sort >"$tmp/staged"
if ! cmp -s "$tmp/from-deb" "$tmp/staged"; then
	diff "$tmp/from-deb" "$tmp/staged" >&2 || true
	fail "the staged files are not the .deb's"
fi
# And the tree on disk is what the listing says, byte for byte.
(cd "$stage/root" && find . -type f -printf '%P\n' | sort | while read -r path; do
	printf '%s %s\n' "$path" "$(sum "$path")"
done) >"$tmp/on-disk"
cmp -s "$tmp/on-disk" "$tmp/staged" || fail "the staged tree is not what files.txt lists"
if grep -q dpkg "$stage/root/usr/lib/epistle/configure"; then fail "configure still speaks of dpkg"; fi
echo "ok    the staged payload is the .deb's, $(wc -l <"$tmp/staged") files"
