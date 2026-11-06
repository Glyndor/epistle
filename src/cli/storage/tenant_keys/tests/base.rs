//! `storage tenant-keys migrate`: refusals, the journal and a resumed run.

use super::*;
use crate::storage::EnvelopeKind;
use crate::storage::rekey::tests::fixture::{Fixture, fixture};

fn options(direction: Direction) -> Options {
	Options {
		direction,
		dry_run: false,
		json: false,
		live: false,
	}
}

fn call(
	fx: &Fixture,
	crypto: &MessageCrypto,
	options: &Options,
	hooks: &mut dyn Hooks,
) -> (ExitCode, String, String) {
	let mut out = Vec::new();
	let mut status = Vec::new();
	let code = migrate(fx.data_dir(), crypto, options, hooks, &mut out, &mut status);
	(
		code,
		String::from_utf8(out).expect("utf8"),
		String::from_utf8(status).expect("utf8"),
	)
}

/// Stops the run just before its rename number `0`, as a power cut would.
struct Cut(usize);

impl Hooks for Cut {
	fn before_replace(&mut self, _original: &Path) -> std::io::Result<()> {
		if self.0 == 0 {
			return Err(std::io::Error::other("power cut"));
		}
		self.0 -= 1;
		Ok(())
	}
}

#[test]
fn forward_needs_tenant_keys_on_and_rollback_needs_it_off() {
	let fx = fixture();
	let path = fx.store("alice", "new/0001.eml", b"alice");
	let before = std::fs::read(&path).expect("read");
	let (code, _, status) = call(
		&fx,
		&fx.crypto_writing(false),
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("tenant_keys = true"), "{status}");
	let (code, _, status) = call(
		&fx,
		&fx.crypto_writing(true),
		&options(Direction::Rollback),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("tenant_keys = false"), "{status}");
	assert_eq!(
		std::fs::read(&path).expect("read"),
		before,
		"nothing was touched"
	);
}

#[test]
fn with_no_tenant_key_a_forward_run_is_a_server_key_rotation() {
	let fx = fixture();
	fx.store("alice", "new/0001.eml", b"alice");
	let (code, out, status) = call(
		&fx,
		&fx.server_only(),
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	assert!(
		out.contains("alice: rewrote 0 file(s) under the server key"),
		"{out}"
	);
}

#[test]
fn a_running_server_is_refused_but_a_dry_run_is_not() {
	let fx = fixture();
	fx.store("alice", "new/0001.eml", b"alice");
	let crypto = fx.crypto_writing(true);
	let mut live = options(Direction::Forward);
	live.live = true;
	let (code, _, status) = call(&fx, &crypto, &live, &mut rekey::NoHooks);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("server is running"), "{status}");
	live.dry_run = true;
	let (code, out, _) = call(&fx, &crypto, &live, &mut rekey::NoHooks);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("alice: would rewrite 1 file(s)"), "{out}");
	assert_eq!(
		journal::read(fx.data_dir()).expect("read"),
		None,
		"a dry run keeps no journal"
	);
}

#[test]
fn a_cut_run_is_journalled_and_the_next_run_finishes_it() {
	let fx = fixture();
	let crypto = fx.crypto_writing(true);
	// "alice" sorts first: two messages move to acme's key. "bob" is in no
	// tenant and holds one message under acme's key, which moves back to the
	// server key; the cut lands on that third rename.
	let alice = [
		fx.store("alice", "new/0001.eml", b"one"),
		fx.store("alice", "new/0002.eml", b"two"),
	];
	let misplaced = crypto
		.seal_for(&KeyOwner::Tenant("acme".into()), b"three")
		.expect("seal");
	let bob = fx.write_raw("bob", "new/0003.eml", &misplaced);

	let (code, _, status) = call(&fx, &crypto, &options(Direction::Forward), &mut Cut(2));
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("bob: power cut"), "{status}");
	assert!(status.contains("resumes when run again"), "{status}");
	let recorded = journal::read(fx.data_dir())
		.expect("read")
		.expect("journal");
	assert_eq!(recorded.done, vec!["alice".to_string()]);
	assert_eq!(recorded.rewritten, 2);
	assert_eq!(
		crypto
			.decode(&std::fs::read(&bob).expect("read"))
			.expect("open"),
		b"three"
	);

	let (code, out, _) = call(
		&fx,
		&crypto,
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!out.contains("alice"), "alice is done and skipped: {out}");
	assert!(
		out.contains("bob: rewrote 1 file(s) under the server key"),
		"{out}"
	);
	assert_eq!(
		journal::read(fx.data_dir()).expect("read"),
		None,
		"finished runs clean up"
	);
	for path in alice {
		let stored = std::fs::read(path).expect("read");
		assert!(matches!(
			crate::storage::envelope_kind(&stored),
			EnvelopeKind::V2(_)
		));
	}
	let stored = std::fs::read(&bob).expect("read");
	assert_eq!(crate::storage::envelope_kind(&stored), EnvelopeKind::V1);
}

#[test]
fn a_run_in_the_other_direction_waits_for_the_unfinished_one() {
	let fx = fixture();
	let mut unfinished = Journal::new(Direction::Forward);
	unfinished.done.push("alice".into());
	journal::write(fx.data_dir(), &unfinished).expect("journal");
	let (code, _, status) = call(
		&fx,
		&fx.crypto_writing(false),
		&options(Direction::Rollback),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("unfinished forward run"), "{status}");
}

#[test]
fn accounts_a_journal_marks_done_are_skipped_on_resume() {
	let fx = fixture();
	let crypto = fx.crypto_writing(true);
	let path = fx.store("alice", "new/0001.eml", b"one");
	let before = std::fs::read(&path).expect("read");
	let mut resumed = Journal::new(Direction::Forward);
	resumed.done.push("alice".into());
	journal::write(fx.data_dir(), &resumed).expect("journal");
	let (code, out, _) = call(
		&fx,
		&crypto,
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!out.contains("alice"), "{out}");
	assert_eq!(std::fs::read(&path).expect("read"), before);
}

#[test]
fn json_output_names_the_target_of_each_account() {
	let fx = fixture();
	fx.store("alice", "new/0001.eml", b"one");
	let mut json = options(Direction::Forward);
	json.json = true;
	let (code, out, _) = call(&fx, &fx.crypto_writing(true), &json, &mut rekey::NoHooks);
	assert_eq!(code, ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
	assert_eq!(value["direction"], "forward");
	assert_eq!(value["accounts"][0]["account"], "alice");
	assert_eq!(value["accounts"][0]["target"], "the key of tenant \"acme\"");
	assert_eq!(value["accounts"][0]["rewritten"], 1);
}
