//! Ban-aware IMAP AUTHENTICATE tests: account-side bans and ban clearing.

use super::auth_bans::{decode_server_first, scram_directory_with_ban_store, valid_client_final};
use super::text;
use super::*;
use crate::test_support::fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// A SCRAM account-level ban is enforced: a ban on
/// `account:alice` short-circuits a SCRAM exchange from a fresh IP
/// with the same shape as an IP ban, no record_failure call, and the
/// ban expiry unchanged. The test arms the ban, drives a SCRAM
/// client-first from a different IP than the existing IP-ban tests
/// use, and asserts the wire reply is the same `+`-then-NO a wrong
/// SCRAM proof produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_account_is_refused_before_credential_lookup() {
	let nonce = fixtures::nonce();
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let original_until: u64 = 1_900_000_000;
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: original_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let lookup_counter = crate::smtp::tests::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	// A fresh IP, not banned at the IP level, so a missing account
	// check would let the exchange reach the credential lookup.
	session.set_peer_ip(Some("203.0.113.50".parse().expect("peer")));

	let before = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	let action = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(
		action.collect_auth,
		"a banned account must request a continuation, like a normal exchange"
	);
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CN{nonce},p={bad_proof}");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");
	let after = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);

	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"account ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		after - before,
		0,
		"the SCRAM credential lookup must not happen when an account ban short-circuits the exchange (delta: {})",
		after - before
	);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(ban_store.is_banned("account:alice", now))
	})
	.expect("ban still in force");
	assert_eq!(
		info.until_secs, original_until,
		"the account ban's until_secs must not have moved"
	);
}

/// A SCRAM success clears the ban store: the success path calls
/// `record_ban_outcome` with `success = true`, which routes to
/// `clear_success` for both the IP and the account. A successful
/// proof is the only path that lets a banned subject recover; the
/// PLAIN path does the same thing.
///
/// The test arms bans on both the IP and the account with
/// `until_secs` slightly below the live wall clock, so the recheck
/// at client-first and client-final sees them as expired (the
/// exchange is allowed to run) but the rows are still in the store
/// and visible to a manual query. The test inspects the rows
/// directly so a successful proof that forgot to call
/// `clear_success` would leave them in place, which the assertion
/// would catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_success_clears_ban_store() {
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	// `until_secs` just before the live wall clock: the SCRAM
	// recheck at `unix_now()` sees the rows as expired and lets the
	// exchange through, but a manual query at `until_secs - 1` still
	// sees them. The visible-until-expiry delta is the test's
	// evidence the rows are gone only when `clear_success` ran.
	let visible_until: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
		.saturating_sub(60);
	ban_store.arm_ban(
		"ip:203.0.113.51",
		BanInfo {
			until_secs: visible_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: visible_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	ban_store.arm_ban(
		"pair:alice|203.0.113.51",
		BanInfo {
			until_secs: visible_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.51".parse().expect("peer")));

	// Drive a full successful SCRAM exchange: well-formed client-first,
	// then a valid client-final whose proof matches the real
	// credentials.
	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation");
	let server_first = decode_server_first(&text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a OK"), "{out}");

	assert_eq!(
		ban_store.call_count("clear_success"),
		2,
		"a successful SCRAM exchange must clear the account and the pair, got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	// The two ban rows are gone. Query at `visible_until - 1` so the
	// row is in scope; the only way `is_banned` returns `None` is
	// that `clear_success` actually removed the row.
	let probe = visible_until.saturating_sub(1);
	let ip_info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(ban_store.is_banned("ip:203.0.113.51", probe))
	});
	let account_info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(ban_store.is_banned("account:alice", probe))
	});
	assert!(
		ip_info.is_some(),
		"a success must not clear the client: its own logins would reset its failure count"
	);
	assert!(
		account_info.is_none(),
		"the account ban row must be cleared after a successful SCRAM exchange"
	);
	let pair_info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current()
			.block_on(ban_store.is_banned("pair:alice|203.0.113.51", probe))
	});
	assert!(
		pair_info.is_none(),
		"the pair ban row must be cleared after a successful SCRAM exchange"
	);
}
