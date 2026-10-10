//! Ban-lifecycle SCRAM tests for the SMTP session. Split from
//! `session_tests_scram_bans.rs` to keep both files under the
//! per-file code-line budget. The tests here exercise the
//! lifecycle around a ban refusal: a malformed client-first from
//! a banned IP must not extend the ban, and a ban refusal that
//! outlives its ban must stay refused at client-final. Reuses
//! the `scram_directory_with_ban_store` helper and the SCRAM
//! proof helpers (`decode_server_first`, `scram_challenge_text`,
//! `valid_client_final`) from the sibling ban tests.

use super::tests_scram::{TapEhlo, b64, reply_code};
use super::tests_scram_bans::{
	decode_server_first, scram_challenge_text, scram_directory_with_ban_store, valid_client_final,
};
use super::*;

/// A malformed client-first sent from an already-banned IP does not
/// extend the ban and does not add a strike. The previous behaviour
/// recorded a failure first and only then checked the ban, so an
/// unbanned peer could trip the threshold with bad-base64 requests
/// and then keep extending the ban by reconnecting after the
/// per-connection three-strikes limit closed the socket. The fix
/// consults the IP ban before recording the failure, so a banned
/// peer's garbage requests stay a no-op against the shared store.
/// The test arms an active IP ban, drives three malformed
/// client-firsts (rebuilding the session each time because the
/// per-connection three-strikes limit closes the socket), and
/// asserts the ban expiry has not moved and no new failure landed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_malformed_client_first_while_banned_does_not_extend_ban() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let original_until: u64 = 1_900_000_000;
	ban_store.arm_ban(
		"ip:203.0.113.60",
		BanInfo {
			until_secs: original_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);

	for _ in 0..3 {
		let mut session = Session::new("mail.example.org")
			.with_directory(directory.clone())
			.with_tls_active()
			.with_scram_nonce("SN")
			.tap_ehlo();
		session.set_peer_ip(Some("203.0.113.60".parse().expect("peer")));
		// Invalid base64: bypasses the SCRAM username parse, the
		// credential lookup, and any ban check that runs after the
		// record_failure call.
		assert_eq!(
			reply_code(&session.command_line("AUTH SCRAM-SHA-256 !!!not-base64")),
			535
		);
	}

	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"a banned IP sending garbage must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(ban_store.is_banned("ip:203.0.113.60", now))
	})
	.expect("ban still in force");
	assert_eq!(
		info.until_secs, original_until,
		"the ban's until_secs must not have moved"
	);
}

/// A SCRAM exchange started while a real ban was in force stays
/// refused at client-final even if the ban expires in between. A
/// banned subject who begins the exchange (and gets the
/// server-first with the fake ban-refusal credentials) must not be
/// able to clear or extend the ban row by completing the proof
/// after the ban has been removed: the proof would either succeed
/// against the fake credentials (which never happens because the
/// stored key is all zeros) or fail and re-record a fresh strike
/// (which would re-arm the row, defeating the original ban).
///
/// The test arms an IP ban, drives the client-first, then expires
/// the ban in the store before submitting a valid client-final.
/// The recheck at client-final returns clear (the ban is gone), so
/// a regression that omits the `ban_refusal` flag would let the
/// proof fail and re-record a strike, re-banning the subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_ban_refusal_stays_refused_after_ban_expires() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let original_until: u64 = 1_900_000_000;
	ban_store.arm_ban(
		"ip:203.0.113.61",
		BanInfo {
			until_secs: original_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);

	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce("SN")
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.61".parse().expect("peer")));

	// Start the SCRAM exchange while the ban is in force: the
	// client-first triggers a ban refusal and stashes the fake
	// server in pending_scram with the ban_refusal flag.
	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	// The ban expires before the client-final is sent. A
	// regression that drops the ban_refusal flag would let the
	// recheck see the ban as cleared, let the verifier reject the
	// proof (the fake stored key is all zeros), and record a
	// fresh strike against the IP and the account.
	ban_store.arm_ban(
		"ip:203.0.113.61",
		BanInfo {
			until_secs: 0,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let client_final = valid_client_final("n=alice,r=CN", &server_first, "secret");
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"a ban-refusal exchange that outlives its ban must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a ban-refusal exchange that outlives its ban must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
}
