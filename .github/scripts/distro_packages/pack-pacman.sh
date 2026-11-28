#!/usr/bin/env bash
#
# Stage the amd64 .deb, pack it as a pacman package and prove the result. The
# release and the pull request both run this, so what is checked before a merge is
# what is run before a package is signed.
#
#   pack-pacman.sh DEB VERSION WORK_DIR
#
#   WORK_DIR  receives stage-pacman/ and out/epistle-<V>-1-x86_64.pkg.tar.zst
#
# A second package of a higher version is built from the same payload, in
# upgrade/, so that the check can upgrade over an installed one. It is never
# uploaded.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
deb="${1:?deb}"
version="${2:?version}"
work="${3:?work dir}"

python3 -I "$here/stage_payload.py" --deb "$deb" --version "$version" --arch amd64 \
	--repository "$repo" --out "$work/stage-pacman"
bash "$repo/tests/packaging/payload/verify-matches-deb.sh" "$deb" "$work/stage-pacman"
bash "$here/build-pacman.sh" "$work/stage-pacman" "$work/out" "$version"
# The same payload gives the same bytes, or the package depends on something
# nobody fixed.
bash "$here/build-pacman.sh" "$work/stage-pacman" "$work/again" "$version"
name="epistle-${version}-1-x86_64.pkg.tar.zst"
cmp "$work/out/$name" "$work/again/$name" || { echo "pack-pacman: two builds of the same payload differ" >&2; exit 1; }
echo "ok    two builds of the same payload are the same bytes"

next="${version%.*}.$((${version##*.} + 1))"
bash "$here/build-pacman.sh" "$work/stage-pacman" "$work/upgrade" "$next"
bash "$repo/tests/packaging/pacman/verify-pacman.sh" \
	"$work/out/$name" "$work/stage-pacman" "$version" \
	"$work/upgrade/epistle-${next}-1-x86_64.pkg.tar.zst"
