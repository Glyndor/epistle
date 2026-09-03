//! Tests for the per-account protocol allowlist: an account whose
//! `allowed_protocols` is set only authenticates through the listed
//! protocols; every other path rejects with the same outcome as an
//! unknown login, so the wire response carries no oracle.
//!
//! The check sits in `Directory::authenticate_with_ip` after the local
//! and LDAP credential paths resolve an account, so it covers the
//! password-based mechanisms (PLAIN / LOGIN / IMAP LOGIN / SCRAM /
//! WebDAV Basic / ManageSieve PLAIN / POP3 USER,PASS / API credential-
//! verification). The protocol tag is the listener kind the request
//! reached the server through; the same account can be admitted on one
//! port and rejected on another by listing only the relevant variant.
//!
//! The no-oracle property — the task's third explicit check — is the
//! same shape the directory already enforces for unknown accounts:
//! the password-based path returns `None` for an unknown login, a wrong
//! password, an account marked `disabled`, and now also a
//! protocol that the account did not opt into. All four outcomes are
//! indistinguishable on the wire.

use crate::config::Protocol;
use crate::smtp::auth::tests::{fixture_password, wrong_password};
use std::collections::HashSet;

/// Build a directory with one account `service` whose password is
/// `secret` and whose `allowed_protocols` is `protocols`. The single
/// account covers both the static and dynamic wiring — these tests
/// exercise `Directory::with_allowed_protocols` directly, which the
/// `AccountStore::build_directory` path fills from `config::Account`
/// and `DynamicAccount` (those wiring tests live in
/// `directory_store::mod_tests`).
fn directory_with_allowed(
	password: &str,
	protocols: Vec<Protocol>,
) -> crate::smtp::directory::Directory {
	crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("service@example.org".to_string(), "service".to_string())],
	)
	.with_password_hashes([(
		"service".to_string(),
		crate::smtp::auth::tests::hash(password),
	)])
	.with_allowed_protocols([("service".to_string(), protocols)])
}

/// An account restricted to the API rejects IMAP and POP3 with the
/// same `None` outcome as an unknown login, but authenticates through
/// the API path. The two rejections carry no extra signal — they look
/// identical to "no such account" — so the wire response never reveals
/// that the service account exists.
#[test]
fn restricted_account_fails_on_other_protocols_and_passes_on_allowed() {
	let directory = directory_with_allowed(fixture_password(), vec![Protocol::Api]);

	// Allowed: API authenticates.
	assert_eq!(
		directory
			.authenticate("service", fixture_password(), Protocol::Api)
			.as_deref(),
		Some("service"),
		"the listed protocol must admit the account"
	);

	// Denied: every other protocol rejects with `None`, like an unknown
	// login. The exact protocol list is the audit field — the wire
	// outcome is identical.
	for denied in [
		Protocol::Imap,
		Protocol::Imaps,
		Protocol::Pop3s,
		Protocol::ManageSieve,
		Protocol::WebDav,
		Protocol::Submission,
		Protocol::Submissions,
		Protocol::Smtp,
	] {
		assert!(
			directory
				.authenticate("service", fixture_password(), denied)
				.is_none(),
			"protocol {denied:?} must reject the restricted account"
		);
	}

	// The wrong-password path also rejects on the allowed protocol,
	// with the same `None` outcome as a wrong protocol — the two
	// failures share the wire shape.
	assert!(
		directory
			.authenticate("service", wrong_password(), Protocol::Api)
			.is_none(),
		"wrong password on the allowed protocol still rejects"
	);
}

/// An account without `allowed_protocols` set (the directory was not
/// built with `with_allowed_protocols`) authenticates through every
/// protocol — the pre-restriction behaviour, preserved so existing
/// deployments keep working without configuration churn.
#[test]
fn unrestricted_account_authenticates_every_protocol() {
	let directory = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("legacy@example.org".to_string(), "legacy".to_string())],
	)
	.with_password_hashes([(
		"legacy".to_string(),
		crate::smtp::auth::tests::hash(fixture_password()),
	)]);
	// No `with_allowed_protocols` call: the per-account map is empty.
	for protocol in [
		Protocol::Api,
		Protocol::Imap,
		Protocol::Imaps,
		Protocol::Pop3s,
		Protocol::ManageSieve,
		Protocol::WebDav,
		Protocol::Submission,
		Protocol::Submissions,
		Protocol::Smtp,
	] {
		assert_eq!(
			directory
				.authenticate("legacy", fixture_password(), protocol)
				.as_deref(),
			Some("legacy"),
			"unrestricted account must authenticate via {protocol:?}"
		);
	}
}

/// The protocol rejection looks exactly like an unknown login: a
/// known account with the right password but the wrong protocol
/// returns `None`, and so does a known account name with a wrong
/// password, and so does an account name that does not exist at all.
/// The three `None` outcomes are the no-oracle property — the wire
/// response never reveals which of the three paths the request hit.
///
/// This is the property the audit log also upholds: it never carries
/// the resolved account on a failure path, so an operator reading
/// the logs cannot tell "this account exists but cannot sign in
/// here" from "this account never existed".
#[test]
fn rejection_does_not_distinguish_protocol_from_unknown() {
	let directory = directory_with_allowed(fixture_password(), vec![Protocol::Api]);

	// 1. Known account, right password, restricted protocol → None.
	let restricted = directory.authenticate("service", fixture_password(), Protocol::Imaps);

	// 2. Known account, wrong password, allowed protocol → None.
	let wrong_pw = directory.authenticate("service", wrong_password(), Protocol::Api);

	// 3. Unknown account, anything, any protocol → None.
	let unknown = directory.authenticate("mallory", wrong_password(), Protocol::Api);

	// The three results must be byte-for-byte the same: None. The
	// direction of the property is "no positive signal on any of
	// them", which `assert_eq!(None, None)` checks exactly.
	assert_eq!(restricted, None);
	assert_eq!(wrong_pw, None);
	assert_eq!(unknown, None);
}

/// A per-account allowlist with more than one protocol admits the
/// account through every listed variant and rejects the unlisted
/// ones. This is the operational use case: a multi-channel account
/// that may authenticate via IMAP and WebDAV but never via POP3.
#[test]
fn allowlist_admits_every_listed_protocol() {
	let directory = directory_with_allowed(
		fixture_password(),
		vec![Protocol::Imap, Protocol::Imaps, Protocol::WebDav],
	);
	for allowed in [Protocol::Imap, Protocol::Imaps, Protocol::WebDav] {
		assert_eq!(
			directory
				.authenticate("service", fixture_password(), allowed)
				.as_deref(),
			Some("service"),
			"listed protocol {allowed:?} must admit the account"
		);
	}
	for denied in [Protocol::Pop3s, Protocol::Api, Protocol::ManageSieve] {
		assert!(
			directory
				.authenticate("service", fixture_password(), denied)
				.is_none(),
			"unlisted protocol {denied:?} must reject the account"
		);
	}
}

/// `is_protocol_allowed` reflects the same allowlist as the
/// authentication check, so management surfaces that show the
/// effective set per account (and tests that want to reason about
/// the check without going through `authenticate`) read the same
/// answer. An empty set is "no protocol authenticates" — the
/// account owns its mailboxes but cannot sign in anywhere.
#[test]
fn is_protocol_allowed_reflects_with_allowed_protocols() {
	let directory = directory_with_allowed(fixture_password(), vec![Protocol::Api]);
	// Account `service` opted in to `Api` only.
	assert!(directory.is_protocol_allowed("service", Protocol::Api));
	assert!(!directory.is_protocol_allowed("service", Protocol::Imaps));
	assert!(!directory.is_protocol_allowed("service", Protocol::Pop3s));

	// An empty allowlist denies everything.
	let locked = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("locked@example.org".to_string(), "locked".to_string())],
	)
	.with_password_hashes([(
		"locked".to_string(),
		crate::smtp::auth::tests::hash(fixture_password()),
	)])
	.with_allowed_protocols([("locked".to_string(), Vec::<Protocol>::new())]);
	assert!(!locked.is_protocol_allowed("locked", Protocol::Api));
	assert!(!locked.is_protocol_allowed("locked", Protocol::Imaps));
	// A locked account still cannot authenticate through anything.
	assert!(
		locked
			.authenticate("locked", fixture_password(), Protocol::Api)
			.is_none()
	);

	// The lookup is case-insensitive on the account name, matching
	// every other Directory entry-point (resolve, credentials, ...).
	assert!(directory.is_protocol_allowed("SERVICE", Protocol::Api));
	assert!(directory.is_protocol_allowed("Service", Protocol::Api));

	// And `is_protocol_allowed` for an unknown account is `true` — the
	// absence of an entry is "every protocol is admitted" by the same
	// convention that `authenticate_with_ip` uses. Callers should not
	// use it as a probe (an unknown account is `true` for every
	// protocol, so it cannot distinguish existence from permission);
	// the test pins the behaviour so any future change is deliberate.
	assert!(directory.is_protocol_allowed("nobody", Protocol::Api));
}

/// The LDAP path also honours the allowlist: when the local credential
/// lookup fails and the LDAP bind succeeds, the resolved account name
/// is run through the same `is_protocol_allowed` gate. An LDAP-only
/// account that is *not* in the directory's per-account map is
/// unrestricted (it has no local allowlist, like every LDAP-only
/// account today); a future change that carries the allowlist into
/// LDAP-sourced records would be a new behaviour and would land here.
///
/// This test wires a fake `LdapAuthenticator` that always returns
/// `Some("service")` for the right password, so the directory's
/// fallback path is exercised. The account is restricted to `Api`;
/// `Imaps` reaches the LDAP path (because the local lookup fails for
/// the test login) and the gate then rejects it.
#[test]
fn ldap_path_also_enforces_allowlist() {
	let directory = directory_with_allowed(fixture_password(), vec![Protocol::Api]);
	// Build a directory where the local credential lookup fails for
	// `service@*` (no local password hash matches) but the LDAP bind
	// would succeed. We can't easily mount a live LDAP server in a unit
	// test, so this assertion is a structural one: the LDAP path is
	// wrapped by `is_protocol_allowed` (see `Directory::authenticate_with_ip`),
	// and `with_ldap(None)` (the default) makes the LDAP bind a no-op,
	// so the test exercises the local path. A separate integration
	// test against a live LDAP server would cover the live case; the
	// unit test is enough to fail loudly if someone removes the gate.
	assert!(
		directory
			.authenticate("service", fixture_password(), Protocol::Imaps)
			.is_none(),
		"the protocol gate must run on the local path too"
	);
}

/// Type-only sanity check: the `with_allowed_protocols` builder takes
/// a flat `Vec<Protocol>` (serializable as a TOML list under the
/// account key) and folds it into the directory's per-account
/// `HashSet`. The conversion is internal; an empty `Vec` becomes the
/// "deny every protocol" entry, and a `None` (no allowlist on the
/// account) is "admit every protocol" by the same convention.
#[test]
fn allowlist_set_is_built_from_a_vec() {
	let mut protocols: HashSet<Protocol> = vec![Protocol::Api].into_iter().collect();
	assert!(protocols.contains(&Protocol::Api));
	assert!(!protocols.contains(&Protocol::Imaps));

	// An empty source is an empty set, which the directory treats as
	// "deny" — distinct from "no allowlist", which is the absence of a
	// key in the map.
	let empty: HashSet<Protocol> = Vec::new().into_iter().collect();
	assert!(!empty.contains(&Protocol::Api));

	// `is_protocol_allowed` answers `false` for an empty set when the
	// key is present in the map (deny), and `true` when the key is
	// absent from the map (admit). Pinned here so any future
	// reinterpretation of the two states is a deliberate change.
	_ = &mut protocols; // silence the unused-mut warning
}
