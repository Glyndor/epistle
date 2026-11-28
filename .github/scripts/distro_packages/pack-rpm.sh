#!/usr/bin/env bash
#
# Stage one .deb, pack it as an rpm and prove the result. The release and the pull
# request both run this, so what is checked before a merge is what is run before a
# package is signed.
#
#   pack-rpm.sh DEB VERSION RPM_ARCH WORK_DIR
#
#   WORK_DIR  receives stage-<arch>/ and out/epistle-<V>-1.glyndor.any.<arch>.rpm
#
# For x86_64 a second package of a higher version is built from the same payload,
# in upgrade/, so that the check can upgrade over an installed one. It is never
# uploaded.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
deb="${1:?deb}"
version="${2:?version}"
arch="${3:?x86_64 or aarch64}"
work="${4:?work dir}"

case "$arch" in
	x86_64) deb_arch=amd64 ;;
	aarch64) deb_arch=arm64 ;;
	*) echo "pack-rpm: architecture '$arch' is not x86_64 or aarch64" >&2; exit 1 ;;
esac

python3 -I "$here/stage_payload.py" --deb "$deb" --version "$version" --arch "$deb_arch" \
	--repository "$repo" --out "$work/stage-$arch"
bash "$repo/tests/packaging/payload/verify-matches-deb.sh" "$deb" "$work/stage-$arch"
bash "$here/build-rpm.sh" "$work/stage-$arch" "$work/out" "$version" "$arch"
# The same payload gives the same bytes, or the package depends on something
# nobody fixed.
bash "$here/build-rpm.sh" "$work/stage-$arch" "$work/again" "$version" "$arch"
name="epistle-${version}-1.glyndor.any.${arch}.rpm"
cmp "$work/out/$name" "$work/again/$name" || { echo "pack-rpm: two builds of the same payload differ" >&2; exit 1; }
echo "ok    two builds of the same payload are the same bytes"

upgrade=()
if [ "$arch" = x86_64 ]; then
	next="${version%.*}.$((${version##*.} + 1))"
	bash "$here/build-rpm.sh" "$work/stage-$arch" "$work/upgrade" "$next" "$arch"
	upgrade=("$work/upgrade/epistle-${next}-1.glyndor.any.${arch}.rpm")
fi
bash "$repo/tests/packaging/rpm/verify-rpm.sh" \
	"$work/out/$name" "$work/stage-$arch" "$version" "$arch" "${upgrade[@]}"
