//! Ban-aware IMAP AUTHENTICATE (SASL) tests. Split from
//! `session_tests_auth.rs` to keep both files under the per-file
//! code-line budget. Reuses the `directory()`, `text()`, and
//! `unauth()` helpers from the sibling `auth` module so both files
//! stay in sync.

use super::auth::{directory_with_ban_store, unauth};
use super::text;
use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// A malformed client-first (invalid base64 or a missing username
/// tag) is recorded as a shared-accounting failure: the IP-side
/// strike is recorded even though the login and the resolved account
/// are unknown, so an unbanned peer cannot repeatedly send garbage to
/// avoid the ban store. The first sub-case must send bytes that
/// fail the IMAP base64 decode (so the SCRAM layer never sees
/// them): wrapping the bad string in `B64.encode` would only
/// exercise the missing-username branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_malformed_client_first_records_a_strike() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce("SN");
	session.set_peer_ip(Some("203.0.113.46".parse().expect("peer")));

	// Invalid base64: the bytes that follow the SASL mechanism
	// name are themselves not valid base64, so the IMAP layer
	// fails before the SCRAM client-first handler ever runs. A
	// regression that drops the record_failure call from the
	// IMAP decode-error branch would leave this sub-case with
	// zero strikes recorded.
	let out = text(&session.command_line("a AUTHENTICATE SCRAM-SHA-256 !!!not-base64"));
	assert!(out.contains("a NO"), "{out}");
	// Valid base64 but no username tag: the IMAP layer decodes
	// the SASL continuation line successfully, the SCRAM layer
	// parses the message and finds no `n=` tag.
	let out = text(&session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,x=y")
	)));
	assert!(out.contains("a NO"), "{out}");

	assert_eq!(
		ban_store.call_count("record_failure"),
		2,
		"two malformed client-firsts must record two IP-side strikes, got {}",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.46", 0) >= 2,
		"ban store did not record a strike for ip:203.0.113.46"
	);
}

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
/// Lives in `session_tests_auth_ban_lifecycle.rs` to keep the
/// per-file code-line budget under control.

/// An IMAP LOGIN attempt routes through the directory's
/// `authenticate_with_ip` with the peer IP the network layer recorded
/// on `set_peer_ip`. The test sets up a [`FakeBanStore`], drives LOGIN
/// with a wrong password, and asserts the fake recorded a
/// `record_failure` call keyed on `ip:<peer>`; the subject the
/// directory builds for the peer IP. The directory is the only place
/// that builds `ip:<peer>` strings, so a count of one on the right
/// subject is the proof the peer IP reached the ban path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_login_records_the_peer_ip() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let peer: std::net::IpAddr = "203.0.113.20".parse().expect("peer");
	let mut session = unauth(tmp.path());
	session.directory = directory_with_ban_store(ban_store.clone());
	// The network layer sets the peer IP before the command loop runs.
	session.set_peer_ip(Some(peer));
	let out = text(&session.command_line("a LOGIN alice wrong"));
	assert!(out.contains("a NO"), "{out}");

	assert!(
		ban_store.call_count("record_failure") >= 2,
		"ban store recorded {} failure(s); expected at least two (IP and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.20", 0) >= 1,
		"ban store did not record a failure for ip:203.0.113.20"
	);
	assert!(
		ban_store.failure_count("account:alice", 0) >= 1,
		"ban store did not record a failure for account:alice"
	);
}

/// Build a directory that has SCRAM credentials for `alice` AND has a
/// ban store attached. Used by the ban-interaction tests below to
/// assert IMAP SCRAM consults the ban store before any credential
/// lookup and records the outcome (success clears, failure adds a
/// strike). The optional `lookup_counter` is attached as a
/// per-Directory SCRAM credential-lookup counter; the ban tests
/// inject a fresh atomic here so they can assert the lookup never
/// happened without racing other tests in the same process on a
/// shared counter.
pub(super) fn scram_directory_with_ban_store(
	ban_store: std::sync::Arc<dyn crate::antispam::bans::BanStore>,
	lookup_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
) -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored =
		ScramStored::from_credentials(&ScramCredentials::derive("secret", b"saltsalt", 4096));
	let mut directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::hash("secret"),
	)])
	.with_scram([("alice".to_string(), stored)])
	.with_ban_store(ban_store);
	if let Some(counter) = lookup_counter {
		directory = directory.with_scram_lookup_counter(counter);
	}
	Arc::new(directory)
}

/// A banned IP is refused on IMAP SCRAM before the SCRAM credential
/// lookup runs. The test arms a ban on the peer IP, drives a SCRAM
/// client-first, and asserts the ban store was consulted, the
/// `scram_credentials` lookup count did not move (the exchange was
/// short-circuited), and the wire reply is the same `+`-then-NO a
/// wrong SCRAM proof produces. The lookup count delta is the property
/// that proves a banned IP cannot probe whether an account exists by
/// sending a SCRAM client-first. The test also asserts the salt in
/// the server-first is not the all-zero tell-tale a banned subject
/// could use to distinguish a refusal from a real exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_ip_is_refused_before_credential_lookup() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"ip:203.0.113.42",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let lookup_counter = crate::smtp::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce("SN");
	session.set_peer_ip(Some("203.0.113.42".parse().expect("peer")));

	let before = crate::smtp::directory_scram_test_counter::count(&lookup_counter);
	// A ban refusal at client-first looks like a normal exchange on
	// the wire: a `+` continuation with a server-first, then NO when
	// the proof fails. The wrong-password shape is the same and the
	// test asserts the property is the shape, not the immediate code.
	let action = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(
		action.collect_auth,
		"a ban refusal at client-first must request a continuation, like a normal exchange"
	);
	// The server-first's salt must be derived from the username, not
	// the all-zero pattern that would let a banned subject identify
	// the refusal by the wire shape.
	let server_first = decode_server_first(&text(&action));
	let salt_field = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("s="))
		.expect("s= in server-first");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(salt_field)
		.expect("base64 salt");
	assert_ne!(
		salt,
		vec![0u8; 16],
		"the ban refusal's server-first salt must not be all zeros"
	);
	// The proof is a no-op placeholder; the verifier rejects it
	// because the stored key behind the fake server-first is all
	// zeros. The wire reply is the same NO a wrong password would
	// produce.
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CNSN,p={bad_proof}");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");
	let after = crate::smtp::directory_scram_test_counter::count(&lookup_counter);

	assert!(
		ban_store.call_count("is_banned") >= 1,
		"ban store consulted {} times, expected at least one is_banned",
		ban_store.call_count("is_banned")
	);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		after - before,
		0,
		"the SCRAM credential lookup must not happen when a ban short-circuits the exchange (delta: {})",
		after - before
	);
}

/// A SCRAM failure (a wrong proof against valid credentials) adds one
/// strike to the ban store. The test drives a full SCRAM exchange with
/// a wrong client proof, asserts the wire reply is NO, and asserts the
/// ban store received exactly one `record_failure` call keyed on
/// `ip:<peer>` and one on `account:<login>`, the same keying the PLAIN
/// path uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_failure_adds_one_strike() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce("SN");
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
	let client_final = format!("c=biws,r=CNSN,p={bad_proof}");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");

	assert_eq!(
		ban_store.call_count("record_failure"),
		2,
		"ban store recorded {} failure(s); expected exactly two (IP and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.43", 0) >= 1,
		"ban store did not record a strike for ip:203.0.113.43"
	);
	assert!(
		ban_store.failure_count("account:alice", 0) >= 1,
		"ban store did not record a strike for account:alice"
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
	use crate::antispam::bans::tests::FakeBanStore;
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
	.with_scram_nonce("SN");
	session.set_peer_ip(Some("203.0.113.44".parse().expect("peer")));

	// A ban refusal at client-first still challenges with a `+` and
	// then fails at client-final with NO, the same shape a wrong SCRAM
	// proof produces. The proof is a no-op placeholder; the verifier
	// rejects it because the stored key behind the fake server-first
	// is all zeros.
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CNSN,p={bad_proof}");
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
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory.clone(),
	)
	.with_scram_nonce("SN");
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
	let client_final = valid_client_final("n=alice,r=CN", &server_first, "secret");
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

/// Strip the `+ <base64>\r\n` envelope from a SCRAM continuation
/// reply and decode the base64 payload, so the test can feed the
/// server-first into the SCRAM proof computation.
pub(super) fn decode_server_first(reply: &str) -> String {
	use base64::Engine;
	let trimmed = reply.trim_start_matches("+ ").trim_end_matches("\r\n");
	let raw = base64::engine::general_purpose::STANDARD
		.decode(trimmed)
		.expect("base64 server-first");
	String::from_utf8(raw).expect("utf8 server-first")
}

/// Compute a valid SCRAM-SHA-256 client-final against the given
/// `server_first` for a session whose password is `password`. The
/// `client_first` argument is the bare part of the client-first
/// message (everything after the GS2 header), e.g. `n=alice,r=CN`,
/// because the SCRAM `auth_message` is the bare part, not the full
/// client-first with its `n,,` prefix.
pub(super) fn valid_client_final(client_first: &str, server_first: &str, password: &str) -> String {
	use base64::Engine;
	use ring::{digest, hmac, pbkdf2};
	use std::num::NonZeroU32;

	let salt_field = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("s="))
		.expect("s= in server-first");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(salt_field)
		.expect("base64 salt");
	let combined_nonce = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("r="))
		.expect("r= in server-first");
	let without_proof = format!("c=biws,r={combined_nonce}");
	let auth_message = format!("{client_first},{server_first},{without_proof}");

	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(4096).unwrap(),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
	let client_sig = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
		auth_message.as_bytes(),
	);
	let proof: Vec<u8> = client_key
		.as_ref()
		.iter()
		.zip(client_sig.as_ref())
		.map(|(a, b)| a ^ b)
		.collect();
	format!("{without_proof},p={}", B64.encode(&proof))
}

/// A SCRAM account-level ban is enforced: a ban on
/// `account:alice` short-circuits a SCRAM exchange from a fresh IP
/// with the same shape as an IP ban, no record_failure call, and the
/// ban expiry unchanged. The test arms the ban, drives a SCRAM
/// client-first from a different IP than the existing IP-ban tests
/// use, and asserts the wire reply is the same `+`-then-NO a wrong
/// SCRAM proof produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_account_is_refused_before_credential_lookup() {
	use crate::antispam::bans::tests::FakeBanStore;
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
	let lookup_counter = crate::smtp::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce("SN");
	// A fresh IP, not banned at the IP level, so a missing account
	// check would let the exchange reach the credential lookup.
	session.set_peer_ip(Some("203.0.113.50".parse().expect("peer")));

	let before = crate::smtp::directory_scram_test_counter::count(&lookup_counter);
	let action = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(
		action.collect_auth,
		"a banned account must request a continuation, like a normal exchange"
	);
	let bad_proof = B64.encode([0u8; 32]);
	let client_final = format!("c=biws,r=CNSN,p={bad_proof}");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a NO"), "{out}");
	let after = crate::smtp::directory_scram_test_counter::count(&lookup_counter);

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
	use crate::antispam::bans::tests::FakeBanStore;
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
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce("SN");
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
	let client_final = valid_client_final("n=alice,r=CN", &server_first, "secret");
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(out.contains("a OK"), "{out}");

	assert_eq!(
		ban_store.call_count("clear_success"),
		2,
		"a successful SCRAM exchange must clear both IP and account, got {} clear_success calls",
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
		ip_info.is_none(),
		"the IP ban row must be cleared after a successful SCRAM exchange"
	);
	assert!(
		account_info.is_none(),
		"the account ban row must be cleared after a successful SCRAM exchange"
	);
}
