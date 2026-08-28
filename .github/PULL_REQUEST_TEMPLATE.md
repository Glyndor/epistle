## Summary

<!-- What does this PR do? 1-3 bullet points. -->

## Changes

<!-- List the main changes made. -->

## Test plan

<!-- How was this tested? Check all that apply. -->

- [ ] `cargo fmt --all --check` is clean
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo test --locked --all-features --workspace` passes locally
- [ ] `cargo test --locked --test database` passes against a live Postgres, if this PR touches `migrations/`, `src/db/**` or `tests/database.rs`
- [ ] `cargo test --locked --test interop` passes against a live Postfix, if this PR touches `src/smtp/**`, `src/imap/**`, `src/queue/**`, `src/storage/**` or `src/tls/**`
- [ ] `cargo test --locked --test e2e` passes against a live `epistle` under `systemd`, if this PR touches `src/**` or `tests/e2e.rs`

<!--
A test that was not watched fail is not a test. If this PR adds or changes
a check, say which control you removed to make it go red, and what it
reported. See standards/testing, "Three ways a sabotage lies to you".
-->

- [ ] New or changed checks were verified by deleting the control and watching them fail

## Checklist

- [ ] Targets `develop` (release pull requests into `main` come from `develop` only; `main-guard` refuses any other head branch)
- [ ] Every commit carries a `Signed-off-by:` trailer (`git commit -s`)
- [ ] This pull request body ends with a `Signed-off-by:` trailer, with the same identity as the commits
- [ ] Conventional Commit title on the pull request
- [ ] Labels applied (`type:`, `prio:`, `effort:`, `area:` where applicable)
- [ ] If `Cargo.toml` version was bumped, `debian/changelog` carries a matching entry under the unreleased section
- [ ] If `migrations/` was touched, only new files were added; no applied migration was edited
- [ ] No secrets, keys or credentials in code, logs or fixtures
- [ ] Docs updated if behaviour changed (`docs/configuration.md`, `docs/cli.md`, `docs/dns.md`, `docs/security.md` as needed)

## Related issues

<!-- Closes #123 -->

<!--
`Closes #N` does not auto-close here: GitHub only auto-closes on merges
into the default branch, which is `main`, and fixes land on `develop`
first. The issue is closed by hand when the fix squashes into `develop`.
-->

Signed-off-by: Your Name <you@example.com>