# CI runner

Every Linux job in `.github/workflows/` runs on the runner named by one
repository variable, `CI_RUNNER`:

```yaml
runs-on: ${{ fromJSON(vars.CI_RUNNER || '"ubuntu-latest"') }}
```

With no variable set, the value is `ubuntu-latest`, so the repository behaves
as before. The inner double quotes matter: `fromJSON` parses the value, so a
string needs them and an array works too.

## Turn it on

Settings -> Secrets and variables -> Actions -> Variables -> New repository
variable. Name `CI_RUNNER`, value one of:

- `"my-runner"` (a single label, with the quotes)
- `["self-hosted","linux","x64"]` (several labels, all must match)

The reusable workflows read the variable of the repository that calls them,
not the one that holds them (GitHub's rule for reusable workflows).

## Turn it off

Delete the variable. The next run goes back to `ubuntu-latest`.

## What stays on GitHub's runners

- macOS and Windows jobs, and anything driven by `matrix.os` (`e2e.yml`, the
  `extra-test-os` job of `reusable-rust-ci.yml`), which exist to test that OS.
- The arm64 legs of `release.yml` (`ubuntu-24.04-arm`) and, in the same
  matrices, the amd64 leg, so a release is built on one kind of runner.

## What a self-hosted runner must provide

A job that needs more than a shell only works if the runner has it:

- `container:` jobs (Debian package build in `reusable-rust-debian.yml`):
  Docker or a compatible engine to run the job container.
- `services:` jobs (`db.yml` Postgres, `interop.yml` Postfix): the same engine.
- `container.yml`, and the `podman` option of `reusable-rust-ci.yml`: `podman`
  and a user `podman.socket`.
- `e2e.yml`, `upgrade.yml`: `systemd` and passwordless `sudo`.
- Jobs that run `apt-get` through `sudo` (`reusable-rust-ci.yml`): a Debian or
  Ubuntu image and `sudo`.
- `ubuntu-latest` tooling the images ship by default: `git`, `curl`, `jq`,
  Python 3, `gh`, a C toolchain.

## Security warning

This repository is public. A self-hosted runner executes the code of pull
requests, including pull requests from forks, on your machine.

- Require approval for all outside collaborators' workflow runs
  (Settings -> Actions -> General -> Fork pull request workflows).
- Never use the runner with `pull_request_target`, or any trigger that runs
  fork code with secrets.
- Keep it ephemeral: a fresh container or VM per job, destroyed afterwards,
  with no shared state, credentials or secrets on the host.

## Guard

`tests/workflows/workflow_runner_variable.rs` fails when a Linux `runs-on`
is a literal `ubuntu-latest` or `ubuntu-24.04` instead of the expression.
