//! `epistle account show`: the public view of a static and a dynamic
//! account, never a secret. A sibling of `cli_account_subcommand_tests`,
//! whose harness it reuses, so that suite stays under the line budget.

use super::cli_account_subcommand_tests::{DYNAMIC_NAME, STATIC_NAME, build, reload_store};
use super::*;

#[test]
fn show_prints_public_view_without_secrets() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, DYNAMIC_NAME, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("name: bob"), "{text}");
	assert!(text.contains("source: dynamic"), "{text}");
	assert!(text.contains("addresses: bob@example.org"), "{text}");
	assert!(text.contains("disabled: no"), "{text}");
	assert!(text.contains("quota_bytes: server default"), "{text}");
	assert!(text.contains("protocols: all"), "{text}");
	// The public view must never carry the password hash, the SCRAM
	// credentials, or the TOTP secret.
	assert!(!text.contains("argon2id"), "{text}");
	assert!(!text.contains("scram"), "{text}");
	assert!(!text.contains("totp"), "{text}");
	assert!(!text.contains("password_hash"), "{text}");
}

#[test]
fn show_prints_static_view_without_secrets() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, STATIC_NAME, &mut out),
		ExitCode::SUCCESS,
		"static accounts are addressable through `account show` (read-only)"
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("name: alice"), "{text}");
	assert!(text.contains("source: static"), "{text}");
	assert!(text.contains("addresses: alice@example.org"), "{text}");
	assert!(text.contains("quota_bytes: server default"), "{text}");
	assert!(text.contains("protocols: all"), "{text}");
	// The static view must never carry the password hash.
	assert!(!text.contains("argon2id"), "{text}");
	assert!(!text.contains("password_hash"), "{text}");
}

#[test]
fn show_refuses_unknown_account() {
	let harness = build();
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, "nobody", &mut out),
		ExitCode::from(2),
		"a name that exists nowhere must say so",
	);
}

#[test]
fn show_handles_set_quota_and_protocols() {
	let harness = build();
	let store = reload_store(&harness);
	account::quota_with_store(
		&store,
		DYNAMIC_NAME,
		Some(500 * 1024 * 1024),
		&mut std::io::sink(),
		false,
	);
	account::protocols_with_store(
		&store,
		DYNAMIC_NAME,
		Some(vec![crate::config::Protocol::Api]),
		&mut std::io::sink(),
		false,
	);
	let store = reload_store(&harness);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, DYNAMIC_NAME, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("quota_bytes: 524288000"), "{text}");
	assert!(text.contains("protocols: api"), "{text}");
}
