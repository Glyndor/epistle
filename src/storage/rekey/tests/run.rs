//! A whole run: forward, dry run, rollback and files it cannot open.

use std::os::unix::fs::PermissionsExt;

use super::fixture::{arrival, fixture};
use super::*;

fn acme() -> KeyOwner {
	KeyOwner::Tenant("acme".into())
}

fn run_all(fx: &super::fixture::Fixture, crypto: &MessageCrypto, direction: Direction) -> Totals {
	let mut sum = Totals::default();
	for account in accounts(fx.data_dir()).expect("accounts") {
		let target = target_for(crypto, &account, direction);
		let totals = rekey_account(
			crypto,
			fx.data_dir(),
			&account,
			&target,
			false,
			&mut NoHooks,
		)
		.expect("rekey");
		sum.rewritten += totals.rewritten;
		sum.already += totals.already;
		sum.plaintext += totals.plaintext;
	}
	sum
}

#[test]
fn forward_moves_tenant_mail_and_keeps_bytes_names_and_dates() {
	let fx = fixture();
	let crypto = fx.crypto();
	let mail = fx.store("alice", "new/0001.eml", b"alice one");
	let folder = fx.store("alice", "folders/Work/cur/0002.eml", b"alice two");
	let plain = fx.write_raw("alice", "new/0003.eml", b"from before encryption");
	let blob_dir = fx.data_dir().join("blobs/accounts/alice/ab/cd");
	std::fs::create_dir_all(&blob_dir).expect("mkdir");
	let blob = blob_dir.join("0004");
	std::fs::write(&blob, crypto.encode(b"a blob").expect("seal")).expect("blob");
	let other = fx.store("bob", "new/0005.eml", b"bob's mail");
	let before = fx.files();

	let totals = run_all(&fx, &crypto, Direction::Forward);
	assert_eq!(
		(totals.rewritten, totals.already, totals.plaintext),
		(3, 1, 1)
	);
	assert_eq!(fx.files(), before, "no file added or lost");
	let acme_id = crypto
		.key_listing()
		.into_iter()
		.find(|(owner, _)| *owner == acme())
		.map(|(_, id)| id)
		.expect("acme");
	for (path, body) in [
		(&mail, &b"alice one"[..]),
		(&folder, b"alice two"),
		(&blob, b"a blob"),
	] {
		let stored = std::fs::read(path).expect("read");
		assert_eq!(
			crate::storage::envelope_kind(&stored),
			EnvelopeKind::V2(acme_id)
		);
		assert_eq!(crypto.decode(&stored).expect("open"), body);
		// The server key alone no longer opens it.
		assert!(fx.server_only().decode(&stored).is_err());
	}
	let meta = std::fs::metadata(&mail).expect("meta");
	assert_eq!(
		meta.modified().expect("mtime"),
		arrival(),
		"INTERNALDATE kept"
	);
	assert_eq!(meta.permissions().mode() & 0o777, 0o600);
	assert_eq!(
		std::fs::read(&plain).expect("plain"),
		b"from before encryption"
	);
	let bob = std::fs::read(&other).expect("bob");
	assert_eq!(
		crate::storage::envelope_kind(&bob),
		EnvelopeKind::V1,
		"no tenant, server key"
	);

	let again = run_all(&fx, &crypto, Direction::Forward);
	assert_eq!(again.rewritten, 0, "a second run has nothing left to do");
}

#[test]
fn a_dry_run_counts_and_writes_nothing() {
	let fx = fixture();
	let crypto = fx.crypto();
	let path = fx.store("alice", "new/0001.eml", b"alice");
	let before = std::fs::read(&path).expect("read");
	let totals = rekey_account(&crypto, fx.data_dir(), "alice", &acme(), true, &mut NoHooks)
		.expect("dry run");
	assert_eq!(totals.rewritten, 1);
	assert_eq!(std::fs::read(&path).expect("read"), before);
}

#[test]
fn rollback_returns_everything_to_what_a_release_without_tenant_keys_reads() {
	let fx = fixture();
	let crypto = fx.crypto();
	let paths = [
		fx.store("alice", "new/0001.eml", b"one"),
		fx.store("alice", "cur/0002.eml", b"two"),
	];
	run_all(&fx, &crypto, Direction::Forward);
	let totals = run_all(&fx, &crypto, Direction::Rollback);
	assert_eq!(totals.rewritten, 2);
	for (path, body) in paths.iter().zip([&b"one"[..], b"two"]) {
		let stored = std::fs::read(path).expect("read");
		assert_eq!(crate::storage::envelope_kind(&stored), EnvelopeKind::V1);
		assert_eq!(
			fx.server_only().decode(&stored).expect("old release reads"),
			body
		);
	}
}

#[test]
fn a_file_whose_key_is_not_loaded_is_reported_and_left_alone() {
	let fx = fixture();
	let sealed = fx
		.globex()
		.seal_for(&KeyOwner::Tenant("globex".into()), b"globex mail")
		.expect("seal");
	let path = fx.write_raw("alice", "new/0001.eml", &sealed);
	let error = rekey_account(
		&fx.crypto(),
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut NoHooks,
	)
	.expect_err("unknown key");
	assert!(error.to_string().contains("not loaded"), "{error}");
	assert_eq!(std::fs::read(&path).expect("read"), sealed);
}

#[test]
fn an_account_in_no_keyed_tenant_targets_the_server_key() {
	let fx = fixture();
	let crypto = fx.crypto();
	assert_eq!(target_for(&crypto, "alice", Direction::Forward), acme());
	assert_eq!(
		target_for(&crypto, "bob", Direction::Forward),
		KeyOwner::Server
	);
	assert_eq!(
		target_for(&crypto, "alice", Direction::Rollback),
		KeyOwner::Server
	);
}
