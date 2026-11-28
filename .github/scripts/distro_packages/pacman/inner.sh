#!/usr/bin/env bash
#
# Runs INSIDE the pacman builder container. Gives the PKGBUILD and the staged tree
# to the build user, runs makepkg once, and copies the one package to /out.
#
# Reads: /stage (read only), /work/PKGBUILD
# Env:   VERSION, SOURCE_DATE_EPOCH
set -euo pipefail

: "${VERSION:?}" "${SOURCE_DATE_EPOCH:?}"

top=/tmp/pkgbuild
rm -rf "$top"
mkdir -p "$top/out"
cp /work/PKGBUILD "$top/PKGBUILD"
cp -a /stage "$top/stage"
chown -R build:build "$top"
cd "$top"
# The dependencies are the host's business: none is needed to copy files.
runuser -u build -- env \
	EPISTLE_VERSION="$VERSION" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
	PACKAGER="Glyndor <noreply@glyndor.net>" PKGDEST="$top/out" PKGEXT=.pkg.tar.zst \
	makepkg --nodeps --noconfirm >/tmp/makepkg.log 2>&1 || { cat /tmp/makepkg.log >&2; exit 1; }

built=("$top"/out/*.pkg.tar.zst)
if [ "${#built[@]}" != 1 ] || [ ! -f "${built[0]}" ]; then
	echo "makepkg did not produce exactly one package" >&2
	exit 1
fi
cp "${built[0]}" /out/
chmod 0644 "/out/$(basename "${built[0]}")"
