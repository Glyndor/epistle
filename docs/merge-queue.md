# Merge queue

`develop` can merge through GitHub's merge queue. The workflows are ready for
it; switching it on is a setting in the `protect-develop` ruleset, which the
owner changes.

## What runs in the queue

When a pull request enters the queue, GitHub builds a temporary branch
`gh-readonly-queue/develop/pr-<N>-<sha>` and fires the `merge_group` event
(`types: [checks_requested]`) on it. `paths:` and `branches:` filters do not
apply to that event. A required check that does not report there leaves the
entry waiting until the queue times out, so each workflow that emits a
required check carries `merge_group` at the top level:

| required check | workflow |
|---|---|
| `rust / Format & lint`, `rust / Test`, `rust / Coverage` | `ci.yml` |
| `dco / Signed-off-by present on every commit` | `dco.yml` |
| `line-limit / line limit` | `line-limit.yml` |
| `debian / dpkg-buildpackage` | `debian.yml` |
| `sbom-and-licenses / SBOM and license attribution` | `supply-chain.yml` |

Workflows with path filters that are not required (`container`, `db`, `e2e`,
`imaptest`, `interop`, `ldap`, `fuzz`, `upgrade`) do not run in the queue, and
neither does `dependabot-freshness` in `ci.yml`. They run on the pull request.

`dco` reads its commit range from the event: on `merge_group` it is the
squash commit GitHub built, so the trailer is checked on the commit that
lands on `develop`. That makes the `Signed-off-by:` trailer in the pull
request body count, as the squash commit message is built from it.

## Enabling it

In the `protect-develop` ruleset, add the "Require merge queue" rule with:

- merge method: squash;
- group size: build 1 and merge at most 1 (the checks are slow and the
  repository is small, so batching buys little and a failure would drop the
  whole group);
- keep the seven required checks above as they are.

Do not add `merge_group` to any other workflow, `release.yml` in particular.

## Keeping it working

`.github/scripts/check_merge_group_triggers.py` (run by
`merge-group-triggers.yml`, tested by `test_check_merge_group_triggers.py`)
fails when a required check has no caller with `merge_group`, when a job that
emits one is renamed, or when another workflow carries the trigger. Its list
of required checks must change together with the ruleset.
