use super::*;

fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
		Action::CollectChunk { .. } => 0,
	}
}

fn scram_directory() -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored =
		ScramStored::from_credentials(&ScramCredentials::derive("secret", b"saltsalt", 4096));
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_scram([("alice".to_string(), stored)]),
	)
}

fn scram_session(inject_nonce: bool) -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(scram_directory())
		.with_tls_active();
	if inject_nonce {
		session = session.with_scram_nonce("SN");
	}
	session.command_line("EHLO client.example.org");
	session
}

fn b64(s: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(s)
}

fn b64_bytes(bytes: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A 32-byte stand-in for the tls-server-end-point certificate hash.
const CERT_HASH: &[u8] = b"0123456789abcdef0123456789abcdef";

/// A SCRAM session on a TLS link that also offers channel binding (-PLUS).
fn scram_plus_session() -> Session {
	Session::new("mail.example.org")
		.with_directory(scram_directory())
		.with_tls_active()
		.with_channel_binding(CERT_HASH.to_vec())
		.with_scram_nonce("SN")
		.tap_ehlo()
}

trait TapEhlo {
	fn tap_ehlo(self) -> Self;
}
impl TapEhlo for Session {
	fn tap_ehlo(mut self) -> Self {
		self.command_line("EHLO client.example.org");
		self
	}
}

#[test]
fn scram_plus_negotiates_when_bound() {
	let mut session = scram_plus_session();
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256-PLUS {}",
		b64("p=tls-server-end-point,,n=alice,r=CN")
	));
	assert_eq!(
		reply_code(&action),
		334,
		"bound -PLUS client-first is challenged"
	);
}

#[test]
fn scram_plus_unavailable_without_binding() {
	// No channel binding configured → the -PLUS mechanism is not offered.
	let mut session = scram_session(true);
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256-PLUS {}",
		b64("p=tls-server-end-point,,n=alice,r=CN")
	));
	assert_eq!(reply_code(&action), 504);
}

#[test]
fn scram_plus_wrong_binding_is_rejected() {
	let mut session = scram_plus_session();
	assert_eq!(
		reply_code(&session.command_line(&format!(
			"AUTH SCRAM-SHA-256-PLUS {}",
			b64("p=tls-server-end-point,,n=alice,r=CN")
		))),
		334
	);
	// client-final whose c= carries the wrong binding data.
	let wrong = b64_bytes(b"WRONGWRONGWRONGWRONGWRONGWRONG!!");
	let client_final = format!("c={wrong},r=CNSN,p={}", b64_bytes(&[0u8; 32]));
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
}

#[test]
fn scram_plain_rejects_downgrade_when_bound() {
	// On a link that offers -PLUS, plain SCRAM with `y,,` is a downgrade.
	let mut session = scram_plus_session();
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("y,,n=alice,r=CN")));
	assert_eq!(reply_code(&action), 535);
}

#[test]
fn scram_without_initial_prompts_for_client_first() {
	let mut session = scram_session(true);
	// No initial response → empty 334 challenge, then the client-first lands.
	assert_eq!(reply_code(&session.command_line("AUTH SCRAM-SHA-256")), 334);
	assert_eq!(reply_code(&session.auth_line(&b64("n,,n=alice,r=CN"))), 334);
}

#[test]
fn scram_client_first_without_injected_nonce_challenges() {
	// No injected nonce: exercises the random server-nonce path.
	let mut session = scram_session(false);
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&action), 334);
}

#[test]
fn scram_malformed_client_first_is_rejected() {
	// Invalid base64.
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(&session.command_line("AUTH SCRAM-SHA-256 !!!not-base64")),
		535
	);
	// Valid base64 but no username token.
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,x=y")))),
		535
	);
	// Unknown user (no oracle: same 535 as a bad password).
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(
			&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=ghost,r=CN")))
		),
		535
	);
}

#[test]
fn scram_repeated_failures_close_the_connection() {
	let mut session = scram_session(true);
	session.command_line("AUTH SCRAM-SHA-256 !!!");
	session.command_line("AUTH SCRAM-SHA-256 !!!");
	let action = session.command_line("AUTH SCRAM-SHA-256 !!!");
	assert!(
		matches!(action, Action::Close(_)),
		"third failure must close"
	);
}

/// Build a directory that has SCRAM credentials for `alice` AND has a
/// ban store attached. Used by the ban-interaction tests below to
/// assert SCRAM consults the ban store before any credential lookup and
/// records the outcome (success clears, failure adds a strike).
fn scram_directory_with_ban_store(
	ban_store: std::sync::Arc<dyn crate::antispam::bans::BanStore>,
) -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored =
		ScramStored::from_credentials(&ScramCredentials::derive("secret", b"saltsalt", 4096));
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_scram([("alice".to_string(), stored)])
		.with_ban_store(ban_store),
	)
}

/// A banned IP is refused on SMTP SCRAM before the SCRAM credential
/// lookup runs. The test arms a ban on the peer IP, drives a SCRAM
/// client-first, and asserts the ban store was consulted, the
/// `scram_credentials` lookup count is zero (the exchange was
/// short-circuited), and the wire reply is the same 535 a wrong SCRAM
/// proof produces. The lookup count is the property that proves a
/// banned IP cannot probe whether an account exists by sending a
/// SCRAM client-first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_ip_is_refused_before_credential_lookup() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"ip:203.0.113.42",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone());

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce("SN")
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.42".parse().expect("peer")));

	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256 {}",
		b64("n,,n=alice,r=CN")
	));
	assert_eq!(
		reply_code(&action),
		535,
		"a banned IP must receive the same 535 a wrong SCRAM proof does"
	);

	assert!(
		ban_store.call_count("is_banned") >= 1,
		"ban store consulted {} times, expected at least one is_banned",
		ban_store.call_count("is_banned")
	);
	assert_eq!(
		directory.scram_credentials_calls(),
		0,
		"the SCRAM credential lookup must not happen when a ban short-circuits the exchange"
	);
}

/// A SCRAM failure (a wrong proof against valid credentials) adds one
/// strike to the ban store. The test drives a full SCRAM exchange with
/// a wrong client proof, asserts the wire reply is 535, and asserts the
/// ban store received exactly one `record_failure` call keyed on
/// `ip:<peer>` and one on `account:<login>` — the same keying the PLAIN
/// path uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_failure_adds_one_strike() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::BanPolicy;

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone());

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce("SN")
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.43".parse().expect("peer")));

	// client-first is well-formed; the ban check passes.
	assert_eq!(
		reply_code(&session.command_line(&format!(
			"AUTH SCRAM-SHA-256 {}",
			b64("n,,n=alice,r=CN")
		))),
		334
	);
	// The client-final carries a zeroed proof, so the verifier rejects
	// it. The exact shape of the failure is irrelevant: the point is
	// that the ban store records one strike.
	let bad_proof = b64_bytes(&[0u8; 32]);
	let client_final = format!("c=biws,r=CNSN,p={bad_proof}");
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);

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
/// failure) and the ban's `until_secs` is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_attempts_during_ban_do_not_extend_it() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let original_until: u64 = 1_900_000_000;
	ban_store.arm_ban(
		"ip:203.0.113.44",
		BanInfo {
			until_secs: original_until,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = scram_directory_with_ban_store(ban_store.clone());

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce("SN")
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.44".parse().expect("peer")));

	for _ in 0..3 {
		assert_eq!(
			reply_code(&session.command_line(&format!(
				"AUTH SCRAM-SHA-256 {}",
				b64("n,,n=alice,r=CN")
			))),
			535
		);
	}

	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	// The ban is still in force at the original `until_secs` (the fake
	// stores it verbatim and the refusal path does not touch it).
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let info = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current()
			.block_on(ban_store.is_banned(&"ip:203.0.113.44".to_string(), now))
	})
	.expect("ban still in force");
	assert_eq!(
		info.until_secs, original_until,
		"the ban's until_secs must not have moved"
	);
}
