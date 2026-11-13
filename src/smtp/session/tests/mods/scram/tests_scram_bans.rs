//! Ban-aware SCRAM tests for the SMTP session. Split from
//! `tests_scram.rs` to keep both files under the per-file
//! code-line budget. Pulls the `use super::*;` import the same way
//! the sibling module does, and brings in the ban store and the
//! per-test SCRAM credential-lookup counter from the directory
//! helpers. Reuses the `reply_code`, `b64`, `b64_bytes`, and
//! `TapEhlo` helpers from `tests_scram` so both files stay in sync.

use super::tests_scram::{TapEhlo, b64, b64_bytes, reply_code};
use super::*;
use crate::test_support::fixtures;

/// Build a directory that has SCRAM credentials for `alice` AND has a
/// ban store attached. Used by the ban-interaction tests below to
/// assert SCRAM consults the ban store before any credential lookup and
/// records the outcome (success clears, failure adds a strike). The
/// optional `lookup_counter` is attached as a per-Directory SCRAM
/// credential-lookup counter; the ban tests inject a fresh atomic
/// here so they can assert the lookup never happened without racing
/// other tests in the same process on a shared counter.
pub(in crate::smtp::session::tests::mods) fn scram_directory_with_ban_store(
	ban_store: std::sync::Arc<dyn crate::antispam::bans::BanStore>,
	lookup_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
) -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored = ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		fixtures::salt(),
		4096,
	));
	let mut directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::base::hash(fixtures::password()),
	)])
	.with_scram([("alice".to_string(), stored)])
	.with_ban_store(ban_store);
	if let Some(counter) = lookup_counter {
		directory = directory.with_scram_lookup_counter(counter);
	}
	Arc::new(directory)
}

/// A malformed client-first (invalid base64 or a missing username
/// tag) is recorded as a shared-accounting failure: the IP-side
/// strike is recorded even though the login and the resolved account
/// are unknown, so an unbanned peer cannot repeatedly send garbage to
/// avoid the ban store. Without the recording, three malformed
/// attempts would close the connection (per-connection counter) but
/// leave the shared ban store untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_malformed_client_first_records_a_strike() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.46".parse().expect("peer")));

	// Invalid base64.
	assert_eq!(
		reply_code(&session.command_line("AUTH SCRAM-SHA-256 !!!not-base64")),
		535
	);
	// Valid base64 but no username tag.
	assert_eq!(
		reply_code(&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,x=y")))),
		535
	);

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

// Ban lifecycle tests live in `tests_scram_ban_lifecycle.rs`.
// Keep them separate to stay within the per-file code-line budget.

/// A SCRAM success drives the credential lookup, so the per-test
/// counter is bumped. This is the property that catches a regression
/// where the per-test counter stops being used and a process-wide
/// atomic is used in its place: a ban test that snapshots the
/// per-test counter and asserts the delta is zero would still pass
/// (the per-test counter is not bumped either way), but the
/// per-test counter would lose its diagnostic value because it no
/// longer reflects what `scram_credentials` did for this test. A
/// non-ban exchange that bumps the per-test counter is the only
/// direct evidence the counter is wired to the lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_lookup_counter_is_per_test() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let lookup_counter = crate::smtp::tests::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));

	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.47".parse().expect("peer")));

	let before = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	// A non-banned, well-formed client-first drives a SCRAM credential
	// lookup. The per-test counter must move; otherwise the ban test's
	// "delta is zero when a ban short-circuits" assertion would be a
	// tautology.
	assert_eq!(
		reply_code(
			&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")))
		),
		334
	);
	let after = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	assert_eq!(
		after - before,
		1,
		"a non-banned SCRAM exchange must bump the per-test counter exactly once (delta: {})",
		after - before
	);
}

/// A SCRAM ban triggered between client-first and client-final must
/// not be bypassed by a pending proof. The test arms a ban on the
/// account after the client-first has been challenged, then submits a
/// valid client-final: the exchange is refused with 535, the ban store
/// receives no `record_failure` (a ban refusal is distinct from a
/// credential failure) and no `clear_success` (a valid proof against a
/// now-banned account must not authenticate and must not clear the
/// ban).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_client_final_rechecks_ban() {
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.45".parse().expect("peer")));

	// client-first is well-formed; the ban check passes.
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

	// A valid client-final: the proof matches the real credentials, but
	// the ban recheck at client-final must refuse it.
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
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

/// Strip the `334 <base64>\r\n` envelope from a SCRAM challenge reply
/// and decode the base64 payload, so the test can feed the server-first
/// into the SCRAM proof computation.
pub(in crate::smtp::session::tests::mods) fn decode_server_first(reply: &str) -> String {
	use base64::Engine;
	let trimmed = reply.trim_start_matches("334 ").trim_end();
	let raw = base64::engine::general_purpose::STANDARD
		.decode(trimmed)
		.expect("base64 server-first");
	String::from_utf8(raw).expect("utf8 server-first")
}

/// Render a SCRAM challenge action to its wire text so the test can
/// pull the base64 server-first out of the `334` line.
pub(in crate::smtp::session::tests::mods) fn scram_challenge_text(action: &Action) -> String {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::DiscardChunk { reply: r, .. } => r.to_string(),
		Action::Deliver(r, _) => r.to_string(),
		Action::CollectChunk { .. } => String::new(),
	}
}

/// Compute a valid SCRAM-SHA-256 client-final against the given
/// `server_first` for a session whose password is `password`. The
/// `client_first` argument is the bare part of the client-first
/// message (everything after the GS2 header), e.g. `n=alice,r=CN`,
/// because the SCRAM `auth_message` is the bare part, not the full
/// client-first with its `n,,` prefix.
pub(in crate::smtp::session::tests::mods) fn valid_client_final(
	client_first: &str,
	server_first: &str,
	password: &str,
) -> String {
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
	format!("{without_proof},p={}", b64_bytes(&proof))
}
