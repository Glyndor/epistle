#!/usr/bin/env bash
#
# Runs INSIDE an AlmaLinux 9 or a Fedora container, started by verify-rpm.sh: how
# rpm installs, upgrades and removes the package, around the checks of
# ../host/lifecycle.sh.
#
# Podman 6.2.0 and podup come from the Glyndor channel, which does not serve this
# package yet, so the install ignores dependencies; verify-rpm.sh checked them in
# the header.
#
# Reads: /pkg/$NAME, /upgrade/$UPGRADE. Env: VERSION, NEXT_VERSION, NAME, UPGRADE.
set -Eeuo pipefail
trap 'echo "failed in the container script at line $LINENO: $BASH_COMMAND" >&2' ERR

: "${NAME:?}" "${UPGRADE:?}"

dnf -y --setopt=install_weak_deps=0 install systemd shadow-utils util-linux gawk grep findutils procps-ng \
	>/tmp/dnf.log 2>&1 || { cat /tmp/dnf.log >&2; exit 1; }

package_install() { rpm --install --nodeps "/pkg/$NAME"; }
package_upgrade() { rpm --upgrade --nodeps "/upgrade/$UPGRADE"; }
package_remove() { rpm --erase --nodeps epistle; }
package_installed_version() { rpm -q --qf '%{VERSION}-%{RELEASE}\n' epistle; }
package_verify() {
	[ -z "$(rpm -V --nodeps epistle)" ] || { echo "rpm -V reports changed files" >&2; return 1; }
}

# shellcheck disable=SC1091 # mounted beside this script
. /work/lifecycle.sh
