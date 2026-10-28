//! TOCTOU regression tests for the SCRAM known-network bypass:
//! between the client-first and the client-final, the ban store may
//! be armed (a ban fires) or disarmed (a ban lapses). The flag that
//! drives the success path has to come from the recheck at
//! client-final, not from a value computed at client-first and
//! carried through the session state. The three tests below drive
//! the exchange by steps so the test can change the ban store in
//! between, the same shape the existing
//! `smtp_scram_client_final_rechecks_ban` test uses.
//!
//! (a) account had no ban at client-first, a ban is armed between the
//!     two messages, the network is known, a valid proof authenticates
//!     and the account ban stays in force (a bypass lift must keep the
//!     row).
//! (b) account had a ban and a bypass row at client-first, the ban
//!     lapses between the two messages, a valid proof authenticates
//!     and the success path clears the rows (a normal lift).
//! (c) account had no ban at client-first, a ban is armed between the
//!     two messages, the network is unknown, a valid proof is
//!     refused (a ban that fires in flight rejects).
//!
//! Split from `tests_scram_ban_owner_known_network.rs` to keep
//! that file under the per-file code-line budget.

use super::tests_scram::{TapEhlo, b64, finish_scram, reply_code};
use super::tests_scram_bans::{
	decode_server_first, scram_challenge_text, scram_directory_with_ban_store, valid_client_final,
};
use super::*;
use crate::antispam::bans::tests::FakeBanStore;
use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};
use crate::test_fixtures as fixtures;

/// Build a `BanInfo` with a far-future expiry so the `FakeBanStore`'s
/// `is_banned` filter (`info.until_secs > now_secs`) keeps treating it
/// as in force for the couple of milliseconds the SCRAM exchange runs
/// in. Reused by all three tests to keep the fixture identical across
/// the (a), (b), and (c) cases.
fn far_future_ban(reason: &str) -> BanInfo {
	BanInfo {
		until_secs: u64::MAX,
		reason: reason.to_string(),
	}
}

/// The wall clock the fake compares against, sampled once per test.
fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

async fn is_account_banned(store: &FakeBanStore, account: &str, now: u64) -> bool {
	let subject = format!("account:{account}");
	tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(store.is_banned(&subject, now))
	})
	.is_some()
}

/// (a) client-first is clean (no ban), a ban is armed between the two
/// messages, the network is on the bypass list, a valid proof lets the
/// owner in. The ban row must still be in force at the end: the bypass
/// lift at client-final only refreshes the network row, it must not
/// `clear_success` the ban that fired in flight. The previous code
/// carried the client-first flag (false here, because the ban wasn't
/// armed yet) and so would have called `clear_success`, dropping the
/// row the test now arms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_bypass_toctou_ban_appears_in_flight_keeps_ban() {
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.90";
	let now = now_secs();
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	// Ban appears after the client-first landed: the recheck at
	// client-final must see the ban in flight and treat the exchange as
	// a bypass lift, not as a normal success.
	ban_store.arm_ban(
		"account:alice",
		far_future_ban("5 failed authentications in 900 seconds"),
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		finish_scram(&mut session, &client_final),
		235,
		"a valid SCRAM proof from a known network must succeed even when a ban fires in flight",
	);

	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a bypass lift must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		is_account_banned(&ban_store, "alice", now_secs()).await,
		"the account ban that fired in flight must still be in force",
	);
}

/// (b) client-first already has a ban and a bypass row, but the ban
/// lapses between the two messages. A valid proof must succeed and the
/// success path must `clear_success` both the pair and the account:
/// the lift at client-final comes from a `Clear` recheck, not a
/// `BannedButKnown` one, so the ban row goes away just like a normal
/// successful login. The previous code carried the client-first flag
/// (true here, because the bypass was active at first) and so would
/// have skipped `clear_success`, leaving the row the test now armed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_bypass_toctou_ban_lapses_in_flight_lifts_ban() {
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.91";
	let now = now_secs();
	ban_store.arm_known_network("alice", network, now);
	ban_store.arm_ban(
		"account:alice",
		far_future_ban("5 failed authentications in 900 seconds"),
	);

	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	// Ban lapses between client-first and client-final: re-arm with an
	// already-elapsed `until_secs` so `is_banned` returns None at the
	// recheck, which makes the recheck emit `Clear` instead of
	// `BannedButKnown`. The lifted flag has to come from this recheck,
	// not from the client-first plan that did see the ban.
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: 0,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		finish_scram(&mut session, &client_final),
		235,
		"a valid SCRAM proof after the ban lapses must succeed as a normal login"
	);

	// A normal successful login calls `clear_success` once per subject
	// (pair and account), so a count of two on the fake is the proof
	// the recheck at client-final chose `Clear` rather than
	// `BannedButKnown`.
	assert_eq!(
		ban_store.call_count("clear_success"),
		2,
		"a ban that lapsed in flight must lift just like a normal success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		!is_account_banned(&ban_store, "alice", now_secs()).await,
		"the account ban that lapsed in flight must be gone after a successful login"
	);
}

/// (c) client-first is clean, a ban is armed in flight, the network is
/// not on the bypass list. A valid proof is refused: the recheck at
/// client-final sees a `Banned` outcome (no bypass), so the success
/// path never runs and the ban store receives no `record_failure` (a
/// ban refusal never moves the strike count) and no `clear_success`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_toctou_ban_appears_in_flight_unknown_network_rejects() {
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.92";
	// No bypass row for this network; the recheck must answer `Banned`,
	// not `BannedButKnown`.
	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		reply_code(&session.auth_line(&b64(&client_final))),
		535,
		"a ban that fires in flight on an unknown network must refuse, the same shape a wrong password would",
	);
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
	assert!(
		is_account_banned(&ban_store, "alice", now_secs()).await,
		"the ban that fired in flight must still be in force on an unknown network"
	);
}
