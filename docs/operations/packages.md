# rpm packages

The release builds an rpm package of epistle for x86_64 and aarch64 next to the
`.deb`, packed from the same files: the binary, the completions, the man pages
and the documents are byte for byte those of the `.deb`. A prerelease carries the
`.deb` only.

## Installing and upgrading

The rpm package runs no script on the host. What the `.deb` does in its
`postinst` is one command, run once after installing and again after every
upgrade:

```sh
sudo /usr/lib/epistle/setup
```

It creates the `glyndor-epistle` account and its directories, gives it
subordinate ids, enables linger and the Podman API socket, applies the
unprivileged port floor and, when the stack is enabled, updates it. A step that
does not take is named on stderr with the command that fixes it, as with the
`.deb`. It is safe to run again. After it, set the server up with
`sudo epistle init`.

## What differs from the `.deb`

| | `.deb` | rpm |
|---|---|---|
| Host setup | on every install and upgrade | when `setup` is run |
| Account | created by the `postinst` | declared in `/usr/lib/sysusers.d/epistle.conf`, which systemd applies at install; `setup` applies it again |
| Port floor | `/usr/lib/sysctl.d/30-glyndor-epistle.conf` | `setup` writes `/etc/sysctl.d/99-glyndor-epistle.conf`, unless the host already sets the key; removing the package leaves that file |
| `epistle stack rollback` | goes back to the binary the upgrade replaced | not available: nothing saves the replaced binary |
| `wireguard-tools` | a dependency | install it yourself on a deployment with more than one node |
| Removal | `apt purge` deletes the account, the mail and `/etc/epistle` | removal leaves them; there is no purge |

Neither package ships a file under `/etc`, so an upgrade never replaces
`/etc/epistle/epistle.toml` or anything else you or the server wrote there.
Removing the package leaves the account, the configuration and the mail in place.

`epistle` prints some advice in Debian terms, such as `apt install podup`. Use the
package manager of your distribution for the same package.
