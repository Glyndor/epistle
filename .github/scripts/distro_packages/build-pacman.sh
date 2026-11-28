#!/usr/bin/env bash
#
# Build epistle-<V>-1-x86_64.pkg.tar.zst from a staged payload.
#
#   build-pacman.sh STAGE_DIR OUT_DIR VERSION
#
#   STAGE_DIR  written by stage_payload.py for amd64
#   OUT_DIR    receives the one package
#   VERSION    X.Y.Z, the tag without `v`
#
# There is no aarch64 package: Arch Linux has no official port, and the channel
# refuses any architecture but x86_64 and any. Nothing is compiled. makepkg runs
# the PKGBUILD in a container built from the pinned Arch image (images.env), with
# no network.
#
# Env: CONTAINER_ENGINE (podman, or docker).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
stage="${1:?stage dir}"
out="${2:?output dir}"
version="${3:?version}"
engine="${CONTAINER_ENGINE:-podman}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "build-pacman: version '$version' is not X.Y.Z" >&2; exit 1; }
if [ ! -d "$stage/root" ] || [ ! -f "$stage/files.txt" ] || [ ! -f "$stage/epoch" ]; then
	echo "build-pacman: $stage is not a staged payload" >&2
	exit 1
fi
epoch="$(cat "$stage/epoch")"
[[ "$epoch" =~ ^[0-9]{1,12}$ ]] || { echo "build-pacman: the epoch of the stage is not a number" >&2; exit 1; }
# Fail on a payload that is not the x86_64 one before packing anything.
if ! head -c 20 "$stage/root/usr/bin/epistle" | od -An -tx1 | tr -d ' \n' | grep -q '^7f454c46.\{28\}3e00'; then
	echo "build-pacman: usr/bin/epistle is not an x86_64 ELF" >&2
	exit 1
fi
mkdir -p "$out"
stage="$(cd "$stage" && pwd)"
out="$(cd "$out" && pwd)"

# shellcheck disable=SC1091 # a sibling file, not followed by the lint
. "$here/images.env"

tag="localhost/epistle-makepkg:$(cat "$here/images.env" "$here/pacman/Containerfile" | sha256sum | cut -c1-16)"
if ! "$engine" image inspect "$tag" >/dev/null 2>&1; then
	# The day of the image, from its version label (YYYYMMDD.revision.build), as the
	# Arch Linux Archive names it. Asked by digest: the engine keeps no tag for it.
	"$engine" pull --quiet "$PACMAN_BUILD_BASE" >/dev/null
	by_digest="$(sed -E 's/:[^:@/]+@/@/' <<<"$PACMAN_BUILD_BASE")"
	built="$("$engine" image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$by_digest")"
	[[ "$built" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})\.[0-9]+\.[0-9]+$ ]] \
		|| { echo "build-pacman: the version label of the builder image names no day: '$built'" >&2; exit 1; }
	snapshot="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/${BASH_REMATCH[3]}"

	"$engine" build --quiet --tag "$tag" --build-arg "BASE=$PACMAN_BUILD_BASE" \
		--build-arg "SNAPSHOT=$snapshot" --file "$here/pacman/Containerfile" "$here/pacman" >/dev/null
fi

name="epistle-${version}-1-x86_64.pkg.tar.zst"
rm -f "$out/$name"
"$engine" run --rm --network none \
	--env "VERSION=$version" --env "SOURCE_DATE_EPOCH=$epoch" \
	--volume "$stage:/stage:ro" \
	--volume "$here/pacman/PKGBUILD:/work/PKGBUILD:ro" \
	--volume "$here/pacman/inner.sh:/work/inner.sh:ro" \
	--volume "$out:/out" \
	"$tag" bash /work/inner.sh
[ -f "$out/$name" ] || { echo "build-pacman: $name was not produced" >&2; exit 1; }
echo "$out/$name"
