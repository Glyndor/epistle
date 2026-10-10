//! End-to-end integration test for `epistle init`. Every test in
//! this binary spawns the real binary against a fresh tempdir and
//! drives a different code path of the apply phase: a dry-run
//! leave-no-trace scenario, the apply-everything scenarios (a
//! fresh tree with `database = false`, the database-on rerun that
//! must keep the password and compose file byte-for-byte), the
//! interactive assistant with both an EOF and a declined
//! confirmation, the skip path when `openssl` is off `PATH`, and
//! the plan-fail-without-effects path on an unparseable existing
//! config. Each topic lives in its own sibling so this entry stays
//! small.

mod apply;
mod dry_run;
mod edge_cases;
mod helpers;
mod interactive;

fn main() {
	// The integration test cases live in the submodules above.
}
