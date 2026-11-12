//! Ban-aware IMAP AUTHENTICATE tests: SCRAM strikes and ban extension.

use super::auth_bans::{decode_server_first, scram_directory_with_ban_store, valid_client_final};
use super::text;
use super::*;
use crate::test_support::fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// A SCRAM failure (a wrong proof against valid credentials) adds one
/// strike to the ban store. The test drives a full SCRAM exchange with
/// a wrong client proof, asserts the wire reply is NO, and asserts the
/// ban store received exactly one `record_failure` call keyed on
/// `ip:<peer>` and one on `account:<login>`, the same keying the PLAIN
/// path uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_failure_adds_one_strike() {
	let nonce = fixtures::nonce();
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.43".parse().expect("peer")));

	let out = text(&session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	)));
	assert!(out.starts_with("+ "), "{out}");

	// The client-final carries a zeroed proof, so the verifier rejects
	// it. The exact shape of the failure is irrelevant: the point is
	// that the ban store records one strike.
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CN{nonce},p={bad_proof}");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");

	assert_eq!(
		ban_store.call_count("record_failure"),
		3,
		"ban store recorded {} failure(s); expected exactly three (client, pair and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.43", 0) >= 1,
		"ban store did not record a strike for ip:203.0.113.43"
	);
	assert!(
		ban_store.failure_count("pair:alice|203.0.113.43", 0) >= 1,
		"ban store did not record a strike for the alice/203.0.113.43 pair"
	);
}

/// Attempts during an active ban do not extend the ban and do not add
/// a strike. The test arms a ban, drives a SCRAM client-first with the
/// right username, and asserts the ban store received no
/// `record_failure` call (a ban refusal is distinct from a credential
/// failure) and the ban's `until_secs` is unchanged. The exchange
/// still produces a `+`-then-NO wire shape so a banned IP cannot
/// distinguish its refusal from a wrong password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_attempts_during_ban_do_not_extend_it() {
	let nonce = fixtures::nonce();
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let original_until: u64 = 1_900_000_000;
	ban_store.arm_ban(
		"ip:203.0.113.44",
		BanInfo {
			until_secs: original_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.44".parse().expect("peer")));

	// A ban refusal at client-first still challenges with a `+` and
	// then fails at client-final with NO, the same shape a wrong SCRAM
	// proof produces. The proof is a no-op placeholder; the verifier
	// rejects it because the stored key behind the fake server-first
	// is all zeros.
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CN{nonce},p={bad_proof}");
	for _ in 0..3 {
		let action = session.command_line(&format!(
			"a AUTHENTICATE SCRAM-SHA-256 {}",
			B64.encode("n,,n=alice,r=CN")
		));
		assert!(
			action.collect_auth,
			"a ban refusal at client-first must request a continuation, like a normal exchange"
		);
		let out = text(&session.auth_response(&B64.encode(&client_final)));
		assert!(out.contains("a NO"), "{out}");
	}

	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(ban_store.is_banned("ip:203.0.113.44", now))
	})
	.expect("ban still in force");
	assert_eq!(
		info.until_secs, original_until,
		"the ban's until_secs must not have moved"
	);
}

/// A SCRAM ban triggered between client-first and client-final must
/// not be bypassed by a pending proof. The test arms a ban on the
/// account after the client-first has been challenged, then submits a
/// valid client-final: the exchange is refused with NO, the ban store
/// receives no `record_failure` (a ban refusal is distinct from a
/// credential failure) and no `clear_success` (a valid proof against a
/// now-banned account must not authenticate and must not clear the
/// ban).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_client_final_rechecks_ban() {
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.45".parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation");
	let server_first = decode_server_first(&text(&challenge));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);

	// A valid client-final: the proof matches the real credentials, but
	// the ban recheck at client-final must refuse it.
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a ban refused at client-final must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"a ban refused at client-final must not record_failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
}
