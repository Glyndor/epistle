# shellcheck shell=bash
# What a person gets from an installed package of epistle, whatever the package
# manager: the account, `setup` (twice, and with an operator's own port floor), an
# upgrade over a configured host, and removal. Sourced inside the container by the
# install script of each format, which defines:
#
#   package_install            install the package built here
#   package_upgrade            upgrade to the package of a later version
#   package_remove             remove it
#   package_installed_version  print <version>-<release> of the installed package
#   package_verify             fail if an installed file differs from the package
#
# No systemd runs in the container: linger and the Podman socket are reported as
# skipped, and /proc/sys is read-only, so the floor is not applied live.
#
# Reads: /stage/files.txt. Env: VERSION, NEXT_VERSION and, set to `required` by a
# format whose installation creates the account by itself, ACCOUNT_AT_INSTALL.

: "${VERSION:?}" "${NEXT_VERSION:?}"
fail() { echo "install: $*" >&2; exit 1; }

floor=/etc/sysctl.d/99-glyndor-epistle.conf
setup=/usr/lib/epistle/setup
account() { getent passwd glyndor-epistle; }
owner() { stat -c '%U:%G %a' "$1"; }
ranges() { grep -c '^glyndor-epistle:' "$1" || true; }

package_install
if account >/dev/null; then
	echo "note: installing the package created the account"
elif [ "${ACCOUNT_AT_INSTALL:-}" = required ]; then
	fail "installing the package did not create the account"
else
	echo "note: installing the package did not create the account; setup has to"
fi
epistle --version | grep -qF "$VERSION" || fail "epistle --version does not say $VERSION"
package_verify
while read -r mode path sha size; do
	test "$(sha256sum "/$path" | cut -d' ' -f1)" = "$sha"
	test "$(stat -c %a "/$path")" = "${mode#0}"
	test "$(stat -c %s "/$path")" = "$size"
done </stage/files.txt
test ! -e /etc/epistle
test ! -e "$floor"

if "$setup" extra >/dev/null 2>&1; then fail "setup took an argument"; fi
if runuser -u nobody -- "$setup" >/dev/null 2>&1; then fail "setup ran without being root"; fi

# An operator's own floor is left alone, and nothing is written over it.
mkdir -p /etc/sysctl.d # the images of some distributions ship none
echo 'net.ipv4.ip_unprivileged_port_start = 80' >/etc/sysctl.d/10-operator.conf
"$setup" >/tmp/setup.log 2>&1 || { cat /tmp/setup.log >&2; fail "setup failed"; }
test ! -e "$floor" || fail "setup wrote a floor over the one of the operator"
account | awk -F: '$3 > 0 && $3 < 1000 && $6 == "/var/lib/glyndor/epistle" && $7 == "/usr/sbin/nologin" { ok = 1 } END { exit !ok }' \
	|| fail "the account is not the one the .deb creates: $(account || echo none)"
rm /etc/sysctl.d/10-operator.conf

"$setup" >/tmp/setup.log 2>&1 || { cat /tmp/setup.log >&2; fail "setup failed the second time"; }
cat /tmp/setup.log
if grep -q dpkg /tmp/setup.log; then fail "setup tells the reader to run dpkg"; fi
grep -qx 'net.ipv4.ip_unprivileged_port_start = 25' "$floor" || fail "setup did not keep the port floor"
test "$(owner /var/lib/glyndor/epistle)" = 'glyndor-epistle:glyndor-epistle 700'
test "$(owner /var/lib/glyndor/epistle/data)" = 'glyndor-epistle:glyndor-epistle 700'
test "$(owner /etc/epistle)" = 'glyndor-epistle:glyndor-epistle 750'
test "$(owner /var/lib/epistle-rollback)" = 'root:root 700'
test "$(ranges /etc/subuid)" = 1
test "$(ranges /etc/subgid)" = 1

# A configured host, upgraded: nothing the operator or the service wrote changes.
printf '# the configuration of the operator\n' >/etc/epistle/epistle.toml
chown glyndor-epistle:glyndor-epistle /etc/epistle/epistle.toml
chmod 0640 /etc/epistle/epistle.toml
echo 'a message' >/var/lib/glyndor/epistle/data/message
echo 'net.ipv4.ip_unprivileged_port_start = 24' >"$floor"
state() {
	sha256sum /etc/epistle/epistle.toml /var/lib/glyndor/epistle/data/message "$floor" /etc/subuid /etc/subgid
	stat -c '%n %U:%G %a' /etc/epistle /etc/epistle/epistle.toml /var/lib/glyndor/epistle /var/lib/glyndor/epistle/data
	account
}
state >/tmp/before
package_upgrade
case "$(package_installed_version)" in
	"$NEXT_VERSION"-*) ;;
	*) fail "the upgrade did not install $NEXT_VERSION" ;;
esac
state >/tmp/after-upgrade
diff /tmp/before /tmp/after-upgrade || fail "the upgrade changed the state of the host"
"$setup" >/tmp/setup.log 2>&1 || { cat /tmp/setup.log >&2; fail "setup failed after the upgrade"; }
state >/tmp/after-setup
diff /tmp/before /tmp/after-setup || fail "setup changed the configuration, the floor, the data or the account"

# Removal takes the files of the package and leaves the account and the mail, as
# `apt remove` does.
package_remove
if package_installed_version >/dev/null 2>&1; then fail "epistle is still installed after its removal"; fi
while read -r _mode path _sha _size; do test ! -e "/$path"; done </stage/files.txt
test ! -e /usr/lib/epistle
test ! -e /usr/share/doc/epistle
test ! -e /usr/share/licenses/epistle
state >/tmp/after-removal
diff /tmp/before /tmp/after-removal || fail "removal changed what the operator keeps"
