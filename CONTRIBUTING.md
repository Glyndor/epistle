# Contributing to Glyndor/epistle

This repository has its own guide because the shared one in `Glyndor/.github`
names branches, test commands and components that belong to a generic flow.
A contributor following it lands on a checklist that points at branches this
repository may not have, or commands this repository never runs.

A second reason the inheritance goes unnoticed: nothing in the repository
expresses it. The files do not appear in the tree, in `git log`, in a clone
or under `grep`. They exist only in GitHub's interface, on the `.github`
profile every Glyndor repository inherits by default. A first-time
contributor reading the inherited guide cannot tell whether the file
describes this repository or some other one, and a reviewer who never
opened the issue tab of this specific repository can spend weeks believing
it does.

Contributions are invitation-only. Bug reports and ideas through issues are
welcome; unsolicited pull requests are not accepted.

## What this repository is

It builds `epistle`, a self-hosted, headless mail server (SMTP, IMAP, POP3,
submission, JMAP, autoconfig, antispam) distributed as a signed Debian
package and through `apt.glyndor.net`. The crate in `Cargo.toml` is the
canonical source of truth for the version; the package published to the apt
archive is built from it under a pinned upstream toolchain and signed with
the org release key.

## Branch flow

```
topic branch ──PR──▶ develop ──release PR──▶ main
                   (squash)         (merge commit)
```

Branch off `develop`, open a pull request against `develop`, squash-merge
back into `develop`. Releases are made by a release pull request from
`develop` into `main`; that one is a **merge commit**, not a squash,
because the merge preserves the exact `develop` history the package was
built from.

A release pull request into `main` whose head branch is not literally
`develop` is refused by `main-guard`. The check exists because the branch
name alone is forgeable (a fork can name any branch `develop`), and the
guarded workflow also requires the head repository to be this one. A
release branch named anything else is rejected.

`Closes #N` does not auto-close here. GitHub only auto-closes issues when
the merge lands on the default branch, which is `main`, and fixes land on
`develop` first. The issue is closed by hand when the fix squashes into
`develop`.

## Before you open a pull request

- **An issue first.** Labels are the tracking system here; there is no
  board. Apply `type:`, `prio:`, `effort:`, `status:` and `area:` where
  they fit.
- **Sign every commit off** with `git commit -s`. The `dco` check is
  required on both `develop` and `main` and it reads every commit on the
  branch.
- **Sign off in the pull request body, not only the commits.** When a
  pull request is squash-merged, GitHub writes the squash commit message
  as the pull request title plus the pull request body. The `dco` check
  looks at the branch commits, not at the squash commit it is about to
  create, so a body without a `Signed-off-by:` trailer lands an
  unsigned-off commit in `develop` with `dco` green beside it, and it
  cannot be repaired after the merge. Add a `Signed-off-by:` trailer at
  the bottom of the body, with the same identity as the commits.
- **Conventional Commit title** on the pull request. It becomes the
  squashed commit message on `develop`.

## Versioning

This repository carries two versions and they must agree. `Cargo.toml`
declares the crate version; `debian/changelog` declares the version of
the package built from it. The release workflow refuses to tag a release
whose crate version differs from its changelog entry, because
`dpkg-buildpackage` takes the `.deb` version from the changelog and
nowhere else, so a changelog left behind produces a package labelled with
the version the user already has and `apt` reports nothing to upgrade.

If the change touches user-visible behaviour, add a changelog entry under
the unreleased section of `debian/changelog` and bump `Cargo.toml` in the
same pull request. The maintainers split the merge commit on `main` if
the two diverge.

## Migrations

Files under `migrations/` are versioned SQL and are applied in numeric
order by `sqlx::migrate!` at startup. An applied migration is never
edited; if a change is needed, add a new migration that follows it. The
current files (`0001_reputation.sql`, `0002_bayes.sql`,
`0003_bayes_scope.sql`, `0004_directory.sql`) are immutable in `develop`
and `main`. A pull request that rewrites one is rejected at review.

## Tests

The suite that runs in CI is:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --workspace
cargo test --locked --test database    # needs a live Postgres; CI provides one
cargo test --locked --test interop     # needs a live Postfix on :1025; CI provides one
cargo test --locked --test e2e         # needs a live epistle under systemd on real ports
cargo bench --no-run --locked          # compiles criterion targets so they never bit-rot
cargo fuzz run <target> -- -max_total_time=60 -timeout=10   # nightly, on protocol parsers
cargo audit
```

The database integration test needs a live Postgres; the interop test
needs a live Postfix on the loopback; the e2e test needs a live `epistle`
under `systemd-run` with self-signed TLS material and the `E2E_*`
environment variables set. The default `cargo test` skips all three when
those are absent.

The coverage gate is 90% with a fixed ignore regex for files that need a
live service or are thin connection-accept glue (see `ci.yml`). The MSRV
build exercises the `rustc` floor `debian/control` promises, currently
1.88, and is pinned to 1.98 to match `ci.yml`'s default toolchain.

Two rules matter more than coverage:

**A test you have not watched fail is not a test.** Before claiming a
check works, delete or invert the control it covers, run it, and confirm
it goes red for the reason it names. Three ways that goes wrong are
written up in `standards/testing`: a sabotage that changes nothing, one
that changes something the test does not look at, and one where the red
comes from somewhere else entirely.

Assert **which** failure fired, never that some failure did. A bare
non-zero assertion is satisfied by almost any failure, including the one
you did not mean.

## Workflows

CI is split by responsibility rather than gathered in one file:

| file | what fails there |
|---|---|
| `ci.yml` | format, clippy, test, coverage, MSRV, dependabot freshness |
| `dco.yml` | a `Signed-off-by:` trailer on every commit |
| `line-limit.yml` | a file's code lines past the soft/hard limit |
| `debian.yml` | the package builds and `Build-Depends` is satisfiable |
| `db.yml` | the database integration test against a live Postgres |
| `e2e.yml` | the full server under `systemd` on `ubuntu-22.04` and `ubuntu-24.04` |
| `interop.yml` | protocol interop against a live Postfix |
| `bench.yml` | the criterion targets compile (run is on-demand) |
| `fuzz.yml` | nightly fuzz on the protocol parsers |
| `rust-audit.yml` | `cargo audit` against current RUSTSEC |
| `supply-chain.yml` | SBOM and license set |
| `main-guard.yml` | a pull request into `main` whose head is not `develop` |
| `release.yml` | the tag, the changelog, the audit and the signing |

Every reusable this repository calls lives under `.github/workflows/` as
a local copy of a named `Glyndor/.github` tag. Nothing is pulled
remotely.

**Job ids are load-bearing.** A required status check is named
`<caller job id> / <inner job name>`, so renaming a job renames its check
and creates a phantom the ruleset still requires, which blocks every
pull request with no explanation. The `develop-only / develop-only` check
on `main` was caused by exactly this: an inline job moved to a reusable
and the ruleset was not updated in the same change, so the 0.4.0 release
sat blocked for four days. Move jobs between files freely; renaming one
is a ruleset change.

## Security

Never open a public issue for a vulnerability. Use the Security tab and
choose **Report a vulnerability**. The organisation's `SECURITY.md`
applies here and is deliberately not duplicated in this repository.
