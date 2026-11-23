# Contributing to Glyndor/epistle

Contributions are invitation-only. Bug reports and ideas through issues are
welcome; unsolicited pull requests are not accepted.

## What this repository is

It builds `epistle`, a self-hosted, headless mail server (SMTP, IMAP, POP3,
submission, JMAP, autoconfig, antispam) distributed as a signed Debian
package and through `apt.glyndor.net`. The crate in `Cargo.toml` is the
canonical source of truth for the version; the package published to the apt
archive is built from it under a pinned upstream toolchain and signed with
the project release key.

## Branch flow

```
topic branch ──PR──▶ develop
```

Branch off `develop`, open a pull request against `develop`, squash-merge
back into `develop`.

## Before you open a pull request

- **An issue first.** Labels are the tracking system here; there is no
  board. Apply `type:`, `prio:`, `effort:`, `status:` and `area:` where
  they fit.
- **Sign every commit off** with `git commit -s`. The `dco` check is
  required and it reads every commit on the branch.
- **Sign off in the pull request body too.** A squash merge writes the pull
  request title and body as the commit message, so end the body with a
  `Signed-off-by:` trailer using the same identity as the commits.
- **Conventional Commit title** on the pull request. It becomes the
  squashed commit message on `develop`.

## Versioning

`Cargo.toml` declares the crate version and `debian/changelog` the version of
the package built from it, and they must agree. If a change touches
user-visible behaviour, add a changelog entry under the unreleased section of
`debian/changelog` and bump `Cargo.toml` in the same pull request.

## Migrations

Files under `migrations/` are versioned SQL and are applied in numeric
order by `sqlx::migrate!` at startup. An applied migration is never
edited; if a change is needed, add a new migration that follows it. Every file
already in `develop` is immutable, and a pull request that rewrites one is
rejected at review. A
migration numbered above 0003 must not drop, rename or retype because
`podman auto-update` cannot roll a migration back, so the discipline is
add and dual-write in one release, read the new shape in the next, and
drop the old shape in the one after that; the test in
`tests/db/core/migrations_expand_contract.rs` enforces it.

## Building from source

```sh
cargo build --release
./target/release/epistle config-check --config mail.toml
./target/release/epistle serve --config mail.toml
```

A source build runs on any Linux without the container stack. Listeners bind
to `127.0.0.1` unless `addr` says otherwise, and the config file must be
owner-only (`chmod 600`). [Configuration](docs/configuration.md) has a full
example and every key.

## Repository layout

[Repository structure](docs/structure.md) has the map. Four rules decide
where code goes:

1. One folder, one module. A folder that mixes two responsibilities is split
   by responsibility, never by size.
2. A module with more than one file becomes a folder with `mod.rs`, and its
   siblings are declared with a plain `mod <sibling>;`.
3. The unit tests of a module live in a `tests/` folder beside it, not in an
   inline block: `foo.rs` declares `#[cfg(test)] mod tests;` and the tests sit
   in `foo/tests/`, and a `mod.rs` keeps them in its own `tests/` folder.
4. `#[path]` reads a data file next to the module. A `#[path]` that splits
   production code means a folder is missing.

The tree is moving to this shape, so some modules do not follow rules 1, 2
and 4 yet. Write new code in this shape, and leave a module you only edit
where it is. A path cited in a doc or a comment has to exist, and `tests/repository/repository_paths_exist.rs` fails on
any that does not.

## Tests

The checks a pull request runs are:

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

To run the e2e test against a server you started yourself, give it a
certificate that is not CA-flagged (the client trusts it as root and leaf),
two TLS listeners and an account:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -days 2 -subj "/CN=mail.epistle.test" \
  -addext "subjectAltName=DNS:mail.epistle.test,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE"

cat > e2e.toml <<'EOF'
hostname = "mail.epistle.test"
data_dir = "/var/lib/epistle-e2e"
domains = ["epistle.test"]
[tls]
cert_file = "cert.pem"
key_file = "key.pem"
[[listeners]]
kind = "submissions"
addr = "127.0.0.1"
port = 4465
[[listeners]]
kind = "imaps"
addr = "127.0.0.1"
port = 4993
EOF
chmod 600 e2e.toml

printf 'a-strong-password' | ./target/release/epistle account-add \
  --config e2e.toml --name tester --address tester@epistle.test
./target/release/epistle serve --config e2e.toml &

E2E_HOST=127.0.0.1 E2E_SUBMISSION_PORT=4465 E2E_IMAPS_PORT=4993 \
  E2E_ACCOUNT=tester@epistle.test E2E_PASSWORD=a-strong-password \
  E2E_CA_PEM=cert.pem cargo test --test e2e
```

The test submits a message over implicit TLS with `AUTH PLAIN`, then polls
IMAPS until it can fetch it.

The coverage gate is 88% with a fixed ignore regex for files that need a
live service or are thin connection-accept glue (see `ci.yml`). The MSRV
build exercises the `rustc` floor `rust-version` declares, currently
1.98 (derived from `mail-parser` 1.0's own `rust-version`). The main CI toolchain is
pinned to 1.100, independently of that minimum.

Two rules matter more than coverage:

**A test you have not watched fail is not a test.** Before claiming a
check works, delete or invert the control it covers, run it, and confirm
it goes red for the reason it names. Three ways that goes wrong: a sabotage that changes nothing, one that
changes something the test does not look at, and one where the red comes
from somewhere else entirely.

Assert **which** failure fired, never that some failure did. A bare
non-zero assertion is satisfied by almost any failure, including the one
you did not mean.

## Required checks

A pull request into `develop` has to pass `CI gate` and
`dco / Signed-off-by present on every commit`. `CI gate` is the last job of
`.github/workflows/ci.yml`: it fails unless the plan succeeded and every suite
(`rust`, `debian`, `line-limit`, `sbom-and-licenses`) either succeeded or was
skipped because the plan said its inputs did not change. The workflow files are
in `.github/workflows/`.

## Security

Never open a public issue for a vulnerability. Use the Security tab and
choose **Report a vulnerability**.

A scratch line used to watch the gate on a documentation-only change.
