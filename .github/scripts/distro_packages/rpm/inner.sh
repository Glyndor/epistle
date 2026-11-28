#!/usr/bin/env bash
#
# Runs INSIDE the rpm builder container. Writes the spec from the template and
# the staged tree, runs rpmbuild once, and copies the one package to /out.
#
# Reads: /stage (read only: root/, files.txt, dirs.txt), /work/epistle.spec.in
# Env:   VERSION, RPM_ARCH (x86_64|aarch64), SOURCE_DATE_EPOCH
set -euo pipefail

: "${VERSION:?}" "${RPM_ARCH:?}" "${SOURCE_DATE_EPOCH:?}"

top=/tmp/rpmbuild
rm -rf "$top"
mkdir -p "$top"/{BUILD,RPMS,SRPMS,SOURCES,SPECS}

# %files: the directories only this package uses, so removing it removes them,
# then every staged file with the mode the stage lists, so rpm does not take it
# from a file system that may have been mounted with another umask.
files=""
while read -r path; do
	files+="%dir %attr(0755, root, root) /${path}"$'\n'
done </stage/dirs.txt
while read -r mode path _sha _size; do
	files+="%attr(${mode}, root, root) /${path}"$'\n'
done </stage/files.txt

# The list goes in through the environment: awk reads backslashes in a -v value.
FILES="$files" awk -v v="$VERSION" '
	{ gsub(/@VERSION@/, v); gsub(/@STAGE@/, "/stage") }
	/^@FILES@$/ { printf "%s", ENVIRON["FILES"]; next }
	{ print }
' /work/epistle.spec.in >"$top/SPECS/epistle.spec"

# _buildhost: rpm writes the build machine's name into the header, which would
# make the same input produce different bytes on different runners.
rpmbuild -bb \
	--target "${RPM_ARCH}-linux" \
	--define "_topdir $top" \
	--define "_buildhost glyndor" \
	--define "_rpmformat 4" \
	"$top/SPECS/epistle.spec" >/tmp/rpmbuild.log 2>&1 || { cat /tmp/rpmbuild.log >&2; exit 1; }

built=("$top"/RPMS/"$RPM_ARCH"/*.rpm)
if [ "${#built[@]}" != 1 ] || [ ! -f "${built[0]}" ]; then
	echo "rpmbuild did not produce exactly one package" >&2
	exit 1
fi
cp "${built[0]}" /out/
chmod 0644 "/out/$(basename "${built[0]}")"
