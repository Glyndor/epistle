#!/bin/sh
# Prepare this host for epistle.
#
# The rpm package runs no script on the host when it is installed or upgraded,
# so what the Debian package does in its postinst is done here, by the person who
# installed it:
#
#   sudo /usr/lib/epistle/setup
#
# Run it once after installing and again after every upgrade. It is safe to run
# more than once: each step only does what is still missing. It creates the
# glyndor-epistle account, runs `configure` (the postinst of the Debian package
# of the same release: directories, subordinate ids, linger, the Podman API
# socket, the unprivileged port floor and, when the stack is enabled, its
# update), and keeps the port floor for the next boot unless this host already
# says something about it.
set -eu

lib=/usr/lib/epistle
floor=$lib/sysctl.d/30-glyndor-epistle.conf
floor_kept=/etc/sysctl.d/99-glyndor-epistle.conf
floor_pattern='^[[:space:]]*-?net[./]ipv4[./]ip_unprivileged_port_start[[:space:]]*='

if [ "$#" -ne 0 ]; then
	echo "usage: sudo $lib/setup" >&2
	exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "epistle: run this as root: sudo $lib/setup" >&2
	exit 1
fi

systemd-sysusers /usr/lib/sysusers.d/epistle.conf

# Decided before `configure`, which applies the floor to the running kernel only.
# Anything the host already says wins: a file that replaces or masks the packaged
# one by name, or any line that sets the key. When the configuration cannot be
# read, nothing is written: lowering the floor of a machine is not a guess.
keep_floor=yes
for taken in "$floor_kept" /etc/sysctl.d/30-glyndor-epistle.conf /run/sysctl.d/30-glyndor-epistle.conf; do
	if [ -e "$taken" ] || [ -L "$taken" ]; then
		keep_floor=no
	fi
done
if [ "$keep_floor" = yes ]; then
	if ! configured=$(systemd-analyze cat-config sysctl.d); then
		keep_floor=no
		echo "epistle: the sysctl configuration could not be read, so the port floor was not kept for the next boot; epistle check boot reports it" >&2
	elif printf '%s\n' "$configured" | grep -Eq -- "$floor_pattern" ||
		grep -Eqs -- "$floor_pattern" /etc/sysctl.conf; then
		keep_floor=no
	fi
fi

"$lib/configure" configure packaged

if [ "$keep_floor" = yes ]; then
	install -D -m 0644 "$floor" "$floor_kept"
	echo "epistle: wrote $floor_kept so the unprivileged port floor is kept after a reboot; delete it to undo that"
fi
