# Proving the stack comes back after a reboot

`epistle check boot` reads what the next reboot depends on. This page is the
other half: a procedure that reboots a machine and checks that the stack came
back. The script is `scripts/stack-reboot/stack-reboot.sh` (bash, `jq`
and `podman` needed; Podman is run as `glyndor-epistle`, or the account in
`STACK_REBOOT_ACCOUNT`).

A reboot only brings the existing containers up. The boot unit runs
`podup up -d --no-build --pull never`, so nothing is built, pulled or
recreated. The script treats any of those as a failure.

## What it checks

`before` reboots the machine, so it runs on a machine you can throw away:

1. It prints what it will do, then refuses unless `--yes-reboot` is given.
2. It refuses a machine that lacks the marker file `/etc/epistle-disposable`,
   unless `--force-not-disposable` is given.
3. It requires the `boot` area of `epistle check boot --json` to be `ok`
   already: a stack that is not healthy before cannot prove anything after.
4. It records, in `/var/lib/stack-reboot` (mode 0700), the name, container id,
   image id, creation time and state of every container, the image ids in the
   account's storage, and the boot id. Nothing else is recorded, so the files
   carry no configuration and no secret.
5. It reboots with `systemctl reboot`.

`after` runs once the machine answers again. It passes only when all of these hold:

- The boot id changed, so a reboot really happened.
- Within `--wait` seconds (default 300) `epistle check boot --json` reports the
  `boot` area `ok` with its `boot unit` and `services` items present and `ok`
  (the unit did not fail and every service that should run is up), and
  `epistle status --json` says the same.
- No container was recreated (same id and same creation time), none runs
  another image, none is gone, none is new, every container that was running is
  running, and no image id appeared. A recreated container is a failure.

It writes a report to `/var/lib/stack-reboot/report.txt` and exits 0 (passed),
1 (verification failed) or 2 (refused or misused). `clean` removes the state.

`--dry-run` on `before` prints the plan and what would be refused, and changes
nothing, with or without `--yes-reboot`.

## Running it on a throwaway machine

Use a virtual machine or a cloud instance you will delete. Never use a
machine that serves mail.

```sh
# On the machine, once: mark it disposable and install the stack.
sudo touch /etc/epistle-disposable
sudo epistle init
sudo epistle stack up

# From a controller, with ssh access (the host name is an example).
VM=epistle-vm.example.net
scp scripts/stack-reboot/stack-reboot.sh "$VM":
ssh "$VM" 'sudo ./stack-reboot.sh before --dry-run'
ssh "$VM" 'sudo ./stack-reboot.sh before --yes-reboot' || true  # the connection drops
until ssh -o ConnectTimeout=5 "$VM" true; do sleep 5; done
ssh "$VM" 'sudo ./stack-reboot.sh after --wait 300'
ssh "$VM" 'sudo ./stack-reboot.sh clean'
```

The second variant starts the stack with `sudo epistle stack update` and
without `stack up`, to prove the unit is installed on that path too. To see the
check fail on purpose, remove the unit before `before` is run
(`sudo epistle stack down` removes it), and `before` refuses because the area
is not `ok`; remove it after `before` records and the `after` run is expected to fail on the
`boot unit` item.

The procedure is run by hand, on a throwaway machine. It must not run on a
machine that is not disposable.

## What is not verified

The script's decisions are tested with fakes (`tests/scripts/stack_reboot.rs`):
the refusals, the dry run, reading the status document, and comparing the
state before and after. The reboot itself is not part of those tests, and
the `podman` output format and the `epistle` documents the script reads are
taken from the source, not from a recorded run. A first run on a real machine
checks those assumptions.
