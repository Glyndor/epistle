# Concurrency invariants

Run `cargo test --locked --test concurrency_suite -- --nocapture`.
Every invariant prints the fixed seed before setup; crash cases also print the
storage mode, selected cut and reached syscall. No external mail server or
new dependency is needed.

- Exactly N final DATA acceptances for 64 parallel submissions by one account.
- Concurrent deliveries stay within one mailbox quota; each final 250 has one
  complete stored copy, with no loss or duplication.
- A login in progress cannot succeed after password replacement or account
  disable returns. This case is neutrally ignored pending lifecycle review.
  Run it explicitly with `cargo test --locked --test concurrency_suite credentials:: -- --ignored --nocapture`.
- SIGKILL during outbound spool and mailbox publication, followed by a real
  child restart: every final 250 survives, and every published message is whole.

The crash invariant uses the test executable as a child and Linux x86_64 ptrace
syscall stops. It needs `/proc` and permission to trace one's own child. A denied
trace or an unreached cut fails; other platforms do not compile this case.
Writes, file syncs and publication renames are cut in a fixed-seed shuffled
order. Temporary unacknowledged files are staging, not published mail. A spool
body without its commit envelope is uncommitted; all committed envelopes must
load a complete body. SIGKILL does not simulate a disk power failure.

The credential case has a positive SCRAM control and a fresh-login negative
control after each mutation. The quota case uses real disk accounting and
storage, without an artificial serialising test sink. Its schedule is a
contention test, not an exhaustive proof of all interleavings.

To check that the submission test can fail, remove the cap on the line
`.with_global_submission_rate_limit(Some(LIMIT as u32));` of `submissions.rs`
(use `None`) and run the test: it accepts all 64 submissions instead of 7 and
fails on the assertion. Restore the line afterwards.
