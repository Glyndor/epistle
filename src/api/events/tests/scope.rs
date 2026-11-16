//! A confined key is told only about what it reaches.

use super::base::confined;
use super::base::{
	ADMIN, QUIET, TENANT_A, TENANT_B, add_account, app, enqueue, fast, log_delivery, settle, state,
	stream, suppress,
};
use crate::api::Principal;
use crate::api::events::sampler::{Sample, changes};
use crate::api::events::topic::{Reach, Topic};

#[tokio::test]
async fn an_account_change_reaches_its_own_tenant_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	let mut tenant_a = stream(&app, TENANT_A, None).await;
	let mut tenant_b = stream(&app, TENANT_B, None).await;
	settle().await;
	add_account(&state, "carol", "carol@b.example");
	let mut told = admin.names(QUIET * 3).await;
	told.sort();
	assert_eq!(told, ["accounts", "status"]);
	let mut told = tenant_b.names(QUIET).await;
	told.sort();
	assert_eq!(told, ["accounts", "status"]);
	assert!(
		tenant_a.names(QUIET).await.is_empty(),
		"a tenant was told about another tenant's account"
	);
	// And the other way round.
	add_account(&state, "dave", "dave@a.example");
	let mut told = tenant_a.names(QUIET * 2).await;
	told.sort();
	assert_eq!(told, ["accounts", "status"]);
	assert!(tenant_b.names(QUIET).await.is_empty());
}

#[tokio::test]
async fn shared_state_is_not_offered_to_a_confined_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	let mut tenant = stream(&app, TENANT_A, None).await;
	settle().await;
	enqueue(&state, "alice@a.example", "someone@elsewhere.example");
	suppress(dir.path(), "x@elsewhere.example");
	log_delivery(dir.path(), "someone@elsewhere.example");
	let mut told = admin.names(QUIET * 3).await;
	told.sort();
	told.dedup();
	assert_eq!(told, ["deliveries", "queue", "status", "suppression"]);
	assert!(
		tenant.names(QUIET * 2).await.is_empty(),
		"a confined key was told about the shared queue, log or list"
	);
}

#[tokio::test]
async fn a_refetch_names_only_what_the_key_may_be_told_about() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut tenant = stream(&app, TENANT_A, Some("1.1")).await;
	let mut told = tenant.names(QUIET).await;
	told.sort();
	assert_eq!(told, ["accounts", "domains", "status"]);
	let mut admin = stream(&app, ADMIN, Some("1.1")).await;
	let mut told = admin.names(QUIET).await;
	told.sort();
	assert_eq!(
		told,
		[
			"accounts",
			"deliveries",
			"domains",
			"queue",
			"status",
			"suppression"
		]
	);
}

fn sample(queue: u64, domains: &[(&str, u64)], accounts: &[(&str, u64, &[&str])]) -> Sample {
	Sample::for_test(queue, domains, accounts)
}

#[test]
fn a_change_is_tagged_with_the_tenants_it_touches() {
	let before = sample(
		1,
		&[("a.example", 1), ("b.example", 1)],
		&[
			("alice", 1, &["alice@a.example"]),
			("bob", 1, &["bob@b.example"]),
		],
	);
	let now = sample(
		1,
		&[("a.example", 1), ("b.example", 2)],
		&[
			("alice", 1, &["alice@a.example"]),
			("bob", 2, &["bob@b.example"]),
		],
	);
	let found = changes(&before, &now);
	assert!(
		found.iter().all(|(_, reach)| *reach != Reach::Everyone),
		"{found:?}"
	);
	let domains = found
		.iter()
		.find(|(topic, _)| *topic == Topic::Domains)
		.expect("domains moved");
	assert_eq!(
		domains.1,
		Reach::Tenants {
			domains: vec!["b.example".to_string()],
			accounts: Vec::new()
		}
	);
	let tenant_a = confined(&["a.example"]);
	let tenant_b = confined(&["b.example"]);
	for (topic, reach) in &found {
		assert!(
			!reach.admits(*topic, &tenant_a),
			"{topic:?} reached a.example"
		);
		assert!(
			reach.admits(*topic, &tenant_b),
			"{topic:?} missed b.example"
		);
		assert!(reach.admits(*topic, &Principal::unrestricted()));
	}
}

#[test]
fn an_account_that_moved_between_tenants_is_told_to_both() {
	let before = sample(1, &[], &[("alice", 1, &["alice@a.example"])]);
	let now = sample(1, &[], &[("alice", 2, &["alice@b.example"])]);
	let found = changes(&before, &now);
	let accounts = found
		.iter()
		.find(|(topic, _)| *topic == Topic::Accounts)
		.expect("accounts moved");
	for who in [["a.example"], ["b.example"]] {
		let key = confined(&who);
		assert!(accounts.1.admits(Topic::Accounts, &key), "{who:?}");
	}
}

#[test]
fn a_removed_account_is_told_to_the_tenant_it_left() {
	let before = sample(1, &[], &[("alice", 1, &["alice@a.example"])]);
	let now = sample(1, &[], &[]);
	let found = changes(&before, &now);
	let accounts = found
		.iter()
		.find(|(topic, _)| *topic == Topic::Accounts)
		.expect("accounts moved");
	assert!(
		accounts
			.1
			.admits(Topic::Accounts, &confined(&["a.example"]))
	);
	assert!(
		!accounts
			.1
			.admits(Topic::Accounts, &confined(&["b.example"]))
	);
}

#[test]
fn a_mass_change_is_split_in_a_bounded_number_of_notifications() {
	let many: Vec<(String, u64, Vec<String>)> = (0..10_000)
		.map(|i| (format!("u{i}"), 2, vec![format!("u{i}@a.example")]))
		.collect();
	let before = Sample::for_test_owned(1, Vec::new(), Vec::new());
	let now = Sample::for_test_owned(1, Vec::new(), many);
	let found = changes(&before, &now);
	let accounts = found.iter().filter(|(t, _)| *t == Topic::Accounts).count();
	assert!((1..=16).contains(&accounts), "{accounts} notifications");
}
