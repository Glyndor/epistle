//! The cap on API keys per account: each scope, administrative keys left out,
//! and creators racing for the last place.

use std::sync::{Arc, Barrier};

use super::*;
use crate::limits::{Gate, Target, test_support::shared};

fn bound(label: &str, account: Option<&str>) -> ApiKey {
	ApiKey {
		grants: Vec::new(),
		label: label.to_string(),
		hash: sha256_hash(label),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![Scope::Send.as_str().to_string()],
		domains: Vec::new(),
		account: account.map(str::to_string),
		auto_submitted: false,
	}
}

fn gate(extra: &str) -> Gate {
	Gate::new(
		shared(extra),
		Target::account("alice", vec!["example.org".into()]),
		"account alice".into(),
	)
}

fn reached(error: &std::io::Error) -> String {
	assert_eq!(error.kind(), std::io::ErrorKind::QuotaExceeded, "{error}");
	error.to_string()
}

#[test]
fn an_account_stops_at_the_cap_and_the_refusal_says_how_to_make_room() {
	let dir = tempfile::tempdir().unwrap();
	let mut store = ApiKeyStore::open(dir.path()).unwrap();
	let gate = gate(
		"[limits]\nmax_api_keys_per_account = 5\n\
		 [[limit_scope]]\naccount = \"alice\"\nmax_api_keys_per_account = 2",
	);
	store
		.add_within(bound("a", Some("alice")), Some(&gate))
		.unwrap();
	store
		.add_within(bound("b", Some("ALICE")), Some(&gate))
		.unwrap();
	let error = store
		.add_within(bound("c", Some("alice")), Some(&gate))
		.expect_err("full");
	let text = reached(&error);
	for part in [
		"account alice",
		"2 API keys per account",
		"set by account alice",
		"revoke an API key",
	] {
		assert!(text.contains(part), "{text:?} lacks {part:?}");
	}
	store
		.add_within(bound("d", Some("bob")), Some(&gate))
		.expect("another account has its own count");
}

#[test]
fn administrative_keys_are_not_counted_and_no_gate_means_no_cap() {
	let dir = tempfile::tempdir().unwrap();
	let mut store = ApiKeyStore::open(dir.path()).unwrap();
	let gate = gate("[limits]\nmax_api_keys_per_account = 1");
	for n in 0..4 {
		store
			.add_within(bound(&format!("admin{n}"), None), Some(&gate))
			.expect("administrative");
	}
	store
		.add_within(bound("mine", Some("alice")), Some(&gate))
		.expect("the first bound key");
	store
		.add(bound("legacy", Some("alice")))
		.expect("add has no gate");
}

#[test]
fn racing_creators_admit_exactly_the_cap() {
	const WRITERS: usize = 8;
	const CAP: usize = 3;
	let dir = tempfile::tempdir().unwrap();
	let barrier = Arc::new(Barrier::new(WRITERS));
	let handles: Vec<_> = (0..WRITERS)
		.map(|n| {
			let (barrier, path) = (Arc::clone(&barrier), dir.path().to_path_buf());
			std::thread::spawn(move || {
				let mut store = ApiKeyStore::open(&path).unwrap();
				let gate = gate(&format!("[limits]\nmax_api_keys_per_account = {CAP}"));
				barrier.wait();
				store.add_within(bound(&format!("k{n}"), Some("alice")), Some(&gate))
			})
		})
		.collect();
	let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
	assert_eq!(
		results.iter().filter(|r| r.is_ok()).count(),
		CAP,
		"{results:?}"
	);
	assert_eq!(ApiKeyStore::open(dir.path()).unwrap().keys().len(), CAP);
}
