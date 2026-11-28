#!/usr/bin/env bash
#
# Runs INSIDE an Arch Linux container, started by verify-pacman.sh: how pacman
# installs, upgrades and removes the package, around the checks of
# ../host/lifecycle.sh.
#
# podup comes from the Glyndor channel, which is not set up here, so its
# dependency is assumed; Podman and the rest are resolved from the repositories of
# Arch, which proves the other dependencies can be satisfied there.
#
# Reads: /pkg/$NAME, /upgrade/$UPGRADE. Env: VERSION, NEXT_VERSION, NAME, UPGRADE.
set -Eeuo pipefail
trap 'echo "failed in the container script at line $LINENO: $BASH_COMMAND" >&2' ERR

: "${NAME:?}" "${UPGRADE:?}"

# NoExtract in the image's pacman.conf leaves out man pages and documents, which
# are part of what is checked.
sed -i '/^NoExtract/d' /etc/pacman.conf
{
	pacman -Syu --noconfirm --disable-sandbox
	pacman -S --noconfirm --needed --disable-sandbox 'podman>=6.2.0' wireguard-tools shadow procps-ng diffutils
} >/tmp/pacman.log 2>&1 || { cat /tmp/pacman.log >&2; exit 1; }

# A hook of systemd applies the sysusers.d entry when pacman installs it.
export ACCOUNT_AT_INSTALL=required
transaction() {
	pacman "$@" --noconfirm --disable-sandbox >/tmp/pacman.log 2>&1 || { cat /tmp/pacman.log >&2; return 1; }
}
package_install() { transaction -U --assume-installed podup=6.0.0 "/pkg/$NAME"; }
package_upgrade() { transaction -U --assume-installed podup=6.0.0 "/upgrade/$UPGRADE"; }
package_remove() { transaction -R epistle; }
package_installed_version() { pacman -Q epistle | awk '{ print $2 }'; }
package_verify() { pacman -Qkk epistle | tail -1 | grep -q ' 0 altered files'; }

# shellcheck disable=SC1091 # mounted beside this script
. /work/lifecycle.sh
