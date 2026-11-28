#!/usr/bin/env bash
#
# The admission of the rpm channel, run over the packages built here.
#
#   admission.sh X86_64_RPM AARCH64_RPM VERSION
#
# The channel refuses a whole release for one package it does not admit, and a
# release is immutable, so what it would say is asked before: its own
# scripts/verify/admit-release.sh and its own configuration, checked out at the
# commit images.env pins. The packages are signed with a key made for this run.
# A tampered package, a release with one architecture and a release with a file
# nobody declared must each be refused, so a check that stopped checking shows.
#
# Needs git, podman (or CONTAINER_ENGINE) and the network (the channel and
# python3-cryptography in the container).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
x86="${1:?x86_64 rpm}"
arm="${2:?aarch64 rpm}"
version="${3:?version}"
engine="${CONTAINER_ENGINE:-podman}"
# shellcheck disable=SC1091 # a sibling file, not followed by the lint
. "$here/../../../.github/scripts/distro_packages/images.env"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/release" "$work/channel"
cp -- "$x86" "$arm" "$work/release/"
git -C "$work/channel" init --quiet
git -C "$work/channel" fetch --quiet --depth 1 https://github.com/Glyndor/rpm "$RPM_CHANNEL_COMMIT"
git -C "$work/channel" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$work/channel" rev-parse HEAD)" = "$RPM_CHANNEL_COMMIT"

"$engine" run --rm \
	--volume "$work/channel:/channel:ro" --volume "$work/release:/release:ro" \
	--volume "$here/admission-in-container.sh:/work/admission.sh:ro" \
	--env "VERSION=$version" \
	"$RPM_QUERY_IMAGE" bash /work/admission.sh
echo "ok    the rpm channel admits the release at $RPM_CHANNEL_COMMIT"
