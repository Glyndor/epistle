//! The caps the account store enforces inside its locked writes: each scope,
//! tightening only, unlimited, and writers racing for the last place.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Barrier};

use super::*;
use crate::directory_store::{AppPassword, AppPasswordStore, DynamicAccount};
use crate::limits::test_support::shared;

fn open(dir: &Path, extra: &str) -> AccountStore {
	AccountStore::open(
		dir,
		["example.com", "example.org", "example.net"]
			.map(String::from)
			.to_vec(),
		HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_limits(shared(extra))
}

fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| a.to_string()).collect(),
		password_hash: "$argon2id$stub".to_string(),
		..DynamicAccount::default()
	}
}

fn capped(result: Result<(), StoreError>) -> String {
	match result {
		Err(StoreError::Capped(reached)) => reached.to_string(),
		_ => panic!("expected a cap"),
	}
}

#[test]
fn nothing_configured_caps_nothing() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(dir.path(), "");
	let many: Vec<String> = (0..60).map(|n| format!("a{n}@example.org")).collect();
	let refs: Vec<&str> = many.iter().map(String::as_str).collect();
	store
		.add(account("bob", &refs))
		.expect("unlimited by default");
	store
		.add_address("bob", "more@example.org")
		.expect("still unlimited");
}

#[test]
fn the_server_cap_stops_a_new_account_with_too_many_addresses() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(dir.path(), "[limits]\nmax_addresses_per_account = 2");
	store
		.add(account("bob", &["a@example.org", "b@example.org"]))
		.expect("two fit");
	let text = capped(store.add(account(
		"eve",
		&["a@example.net", "b@example.net", "c@example.net"],
	)));
	for part in [
		"account eve",
		"2 addresses per account",
		"set by the server",
		"remove an address",
		"max_addresses_per_account",
	] {
		assert!(text.contains(part), "{text:?} lacks {part:?}");
	}
	assert!(store.dynamic("eve").is_none(), "nothing was written");
}

#[test]
fn add_address_stops_at_the_cap_and_names_the_scope_that_set_it() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(
		dir.path(),
		"[[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 2",
	);
	store.add(account("bob", &["a@example.org"])).unwrap();
	store
		.add_address("bob", "b@example.org")
		.expect("the second fits");
	let text = capped(store.add_address("bob", "c@example.org"));
	assert!(text.contains("set by account bob"), "{text}");
	store.add(account("eve", &["a@example.net"])).unwrap();
	store
		.add_address("eve", "b@example.net")
		.expect("another account is not capped");
}

#[test]
fn each_scope_applies_and_a_narrower_one_only_tightens() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(
		dir.path(),
		"[limits]\nmax_addresses_per_account = 4\n\
		 [[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 3\n\
		 [[limit_scope]]\ndomain = \"example.net\"\nmax_addresses_per_account = 2\n\
		 [[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 1",
	);
	let fill = |name: &str, domain: &str, count: usize| {
		let first = format!("{name}0@{domain}");
		store.add(account(name, &[first.as_str()])).unwrap();
		(1..count)
			.map(|n| store.add_address(name, &format!("{name}{n}@{domain}")))
			.collect::<Vec<_>>()
	};
	// Server scope: example.org has no entry of its own.
	assert!(fill("srv", "example.org", 4).iter().all(Result::is_ok));
	let text = capped(store.add_address("srv", "x9@example.org"));
	assert!(text.contains("4 addresses") && text.contains("the server"));
	// Tenant scope: example.com belongs to acme.
	assert!(fill("ten", "example.com", 3).iter().all(Result::is_ok));
	assert!(capped(store.add_address("ten", "x9@example.com")).contains("tenant acme"));
	// Domain scope.
	assert!(fill("dom", "example.net", 2).iter().all(Result::is_ok));
	assert!(capped(store.add_address("dom", "x9@example.net")).contains("domain example.net"));
	// Account scope, under a domain that would allow more.
	assert!(fill("bob", "example.org", 1).iter().all(Result::is_ok));
	assert!(capped(store.add_address("bob", "x9@example.org")).contains("account bob"));
}

#[test]
fn an_account_spanning_domains_gets_the_strictest() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(
		dir.path(),
		"[[limit_scope]]\ndomain = \"example.net\"\nmax_addresses_per_account = 2\n\
		 [[limit_scope]]\ndomain = \"example.org\"\nmax_addresses_per_account = 9",
	);
	store
		.add(account("bob", &["a@example.org", "b@example.org"]))
		.unwrap();
	store
		.add_address("bob", "c@example.org")
		.expect("org alone allows nine");
	let text = capped(store.add_address("bob", "a@example.net"));
	assert!(text.contains("domain example.net"), "{text}");
}

#[test]
fn a_replacement_may_keep_or_drop_addresses_over_a_lowered_cap() {
	let dir = tempfile::tempdir().unwrap();
	let store = open(dir.path(), "");
	store
		.add(account(
			"bob",
			&["a@example.org", "b@example.org", "c@example.org"],
		))
		.unwrap();
	let lowered = open(dir.path(), "[limits]\nmax_addresses_per_account = 2");
	lowered
		.replace_account(
			"bob",
			account("bob", &["a@example.org", "b@example.org", "c@example.org"]),
			None,
		)
		.expect("keeping what exists is allowed");
	lowered
		.replace_account("bob", account("bob", &["a@example.org"]), None)
		.expect("dropping is allowed");
	lowered
		.replace_account(
			"bob",
			account("bob", &["a@example.org", "b@example.org"]),
			None,
		)
		.expect("two fit");
	let text = capped(lowered.replace_account(
		"bob",
		account("bob", &["a@example.org", "b@example.org", "c@example.org"]),
		None,
	));
	assert!(text.contains("2 addresses"), "{text}");
}

#[test]
fn racing_writers_admit_exactly_the_cap_of_addresses() {
	const WRITERS: usize = 8;
	const CAP: usize = 4;
	let dir = tempfile::tempdir().unwrap();
	let extra = format!("[limits]\nmax_addresses_per_account = {CAP}");
	open(dir.path(), &extra)
		.add(account("bob", &["first@example.org"]))
		.unwrap();
	let barrier = Arc::new(Barrier::new(WRITERS));
	let handles: Vec<_> = (0..WRITERS)
		.map(|n| {
			let (barrier, path, extra) = (
				Arc::clone(&barrier),
				dir.path().to_path_buf(),
				extra.clone(),
			);
			std::thread::spawn(move || {
				let store = open(&path, &extra);
				barrier.wait();
				store.add_address("bob", &format!("w{n}@example.org"))
			})
		})
		.collect();
	let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
	let admitted = results.iter().filter(|r| r.is_ok()).count();
	assert_eq!(admitted, CAP - 1, "{results:?}");
	assert!(
		results
			.iter()
			.filter(|r| r.is_err())
			.all(|r| matches!(r, Err(StoreError::Capped(_))))
	);
	let stored = open(dir.path(), "").dynamic("bob").unwrap().addresses.len();
	assert_eq!(stored, CAP);
}

fn app(label: &str) -> AppPassword {
	AppPassword {
		label: label.to_string(),
		hash: "$argon2id$stub".to_string(),
		expires_at: None,
		ip_cidr: None,
		save_sent: None,
	}
}

fn gate(extra: &str) -> crate::limits::Gate {
	crate::limits::Gate::new(
		shared(extra),
		crate::limits::Target::account("alice", vec!["example.org".into()]),
		"account alice".into(),
	)
}

#[test]
fn app_passwords_stop_at_the_cap_of_each_scope() {
	let dir = tempfile::tempdir().unwrap();
	let mut store = AppPasswordStore::open(dir.path()).unwrap();
	let tight = gate(
		"[limits]\nmax_app_passwords_per_account = 3\n\
		 [[limit_scope]]\ndomain = \"example.org\"\nmax_app_passwords_per_account = 2",
	);
	store.add_within("alice", app("one"), Some(&tight)).unwrap();
	store.add_within("alice", app("two"), Some(&tight)).unwrap();
	let error = store
		.add_within("alice", app("three"), Some(&tight))
		.expect_err("full");
	let text = capped(Err(error));
	assert!(
		text.contains("2 app passwords per account") && text.contains("domain example.org"),
		"{text}"
	);
	assert!(text.contains("remove an app password"), "{text}");
	// Without a gate, as before.
	store.add("alice", app("three")).expect("no gate no cap");
}

#[test]
fn racing_app_passwords_admit_exactly_the_cap() {
	const WRITERS: usize = 8;
	const CAP: usize = 3;
	let dir = tempfile::tempdir().unwrap();
	let barrier = Arc::new(Barrier::new(WRITERS));
	let handles: Vec<_> = (0..WRITERS)
		.map(|n| {
			let (barrier, path) = (Arc::clone(&barrier), dir.path().to_path_buf());
			std::thread::spawn(move || {
				let mut store = AppPasswordStore::open(&path).unwrap();
				let gate = gate(&format!("[limits]\nmax_app_passwords_per_account = {CAP}"));
				barrier.wait();
				store.add_within("alice", app(&format!("l{n}")), Some(&gate))
			})
		})
		.collect();
	let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
	assert_eq!(
		results.iter().filter(|r| r.is_ok()).count(),
		CAP,
		"{results:?}"
	);
	let held = AppPasswordStore::open(dir.path())
		.unwrap()
		.for_account("alice")
		.len();
	assert_eq!(held, CAP);
}
