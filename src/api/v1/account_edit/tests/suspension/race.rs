//! The key and the account change between the checks of a request and its
//! write, while the write waits for the account file's lock.

use axum::http::StatusCode;

use super::fixture::*;
use crate::api::api_keys::ApiKey;

const REFUSED: &str = "no such dynamic account";

/// Every way the key `label` stops reaching a suspension, or a resumption,
/// while its request waits.
fn withdrawn(label: &str, secret: &str, domains: &[&str]) -> Vec<(&'static str, Option<ApiKey>)> {
	let held = || key(label, secret, &["manage:write"], domains);
	let mut expired = held();
	expired.expires_at = Some(1);
	let mut elsewhere = held();
	elsewhere.ip_cidr = Some("10.0.0.0/8".to_string());
	let mut bound = held();
	bound.scopes = vec!["write".to_string()];
	bound.account = Some("alice".to_string());
	vec![
		("revoked", None),
		(
			"no scope to write",
			Some(key(label, secret, &["manage:read"], domains)),
		),
		(
			"moved to another tenant",
			Some(key(label, secret, &["manage:write"], &["b.test"])),
		),
		("network changed", Some(elsewhere)),
		("expired", Some(expired)),
		("bound to the account", Some(bound)),
	]
}

/// Changes that leave the key reaching what it asked for: the controls, just
/// inside each limit.
fn kept(label: &str, secret: &str, domains: &[&str]) -> Vec<(&'static str, ApiKey)> {
	let held = || key(label, secret, &["manage:write"], domains);
	let mut here = held();
	here.ip_cidr = Some("127.0.0.0/8".to_string());
	let mut later = held();
	later.expires_at = Some(u64::MAX / 2);
	vec![
		("unchanged", held()),
		("pinned to the client's network", here),
		("expiring later", later),
	]
}

async fn assert_refused_without_a_trace(
	verb: &str,
	label: &'static str,
	bearer: &'static str,
	what: &str,
	now: Option<ApiKey>,
) {
	let world = world();
	let was = verb == "enable";
	world.store.set_disabled("alice", was).expect("prepare");
	let before = std::fs::read(world.store.store_path()).expect("file");
	let path = format!("/api/v1/accounts/alice/{verb}");
	let (status, body, capture) = while_the_write_waits(&world, "POST", &path, bearer, || {
		replace_key(&world, label, now)
	})
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{verb}, {what}: {body}");
	assert_eq!(body["error"]["message"], REFUSED, "{verb}, {what}");
	assert_eq!(
		std::fs::read(world.store.store_path()).expect("file"),
		before,
		"{verb}, {what}: the file was written"
	);
	assert_eq!(disabled(&world, "alice"), was, "{verb}, {what}");
	assert!(capture.events().is_empty(), "{verb}, {what}");
}

async fn assert_written(verb: &str, label: &'static str, bearer: &'static str, now: ApiKey) {
	let world = world();
	let was = verb == "enable";
	world.store.set_disabled("alice", was).expect("prepare");
	let path = format!("/api/v1/accounts/alice/{verb}");
	let (status, body, capture) = while_the_write_waits(&world, "POST", &path, bearer, || {
		replace_key(&world, label, Some(now))
	})
	.await;
	assert_eq!(status, StatusCode::OK, "{verb}: {body}");
	assert_eq!(body["result"], "saved", "{verb}: {body}");
	assert_eq!(disabled(&world, "alice"), !was, "{verb}");
	assert_eq!(capture.events().len(), 1, "{verb}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspension_is_written_only_while_the_key_still_reaches_the_account() {
	for (what, now) in withdrawn("of-a", OF_A, &["a.test"]) {
		assert_refused_without_a_trace("disable", "of-a", OF_A, what, now).await;
	}
	for (_, now) in kept("of-a", OF_A, &["a.test"]) {
		assert_written("disable", "of-a", OF_A, now).await;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resumption_is_written_only_while_the_key_is_still_unconfined() {
	let mut cases = withdrawn("writer", WRITER, &[]);
	// A domain that covers the account is still a confinement.
	cases.push((
		"confined to the account's own domain",
		Some(key("writer", WRITER, &["manage:write"], &["a.test"])),
	));
	for (what, now) in cases {
		assert_refused_without_a_trace("enable", "writer", WRITER, what, now).await;
	}
	for (_, now) in kept("writer", WRITER, &[]) {
		assert_written("enable", "writer", WRITER, now).await;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_moved_to_another_tenant_while_the_write_waits_is_left_alone() {
	let world = world();
	let (status, body, capture) = while_the_write_waits(
		&world,
		"POST",
		"/api/v1/accounts/alice/disable",
		OF_A,
		|| {
			let moved = toml::Value::Array(vec!["alice@b.test".into()]);
			edit_on_disk(&world, "alice", "addresses", moved);
		},
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	assert_eq!(body["error"]["message"], REFUSED);
	let text = std::fs::read_to_string(world.store.store_path()).expect("file");
	assert!(!text.contains("disabled = true"), "{text}");
	assert!(capture.events().is_empty());
}

/// The state the server held when the request arrived says nothing about what
/// the write finds: the answer and the audit line follow the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_audit_line_follows_the_state_found_under_the_lock() {
	for (verb, disk_has, result, kinds) in [
		("disable", true, "unchanged", Vec::<&str>::new()),
		("enable", false, "unchanged", Vec::new()),
		("disable", false, "saved", vec!["account.disabled"]),
		("enable", true, "saved", vec!["account.enabled"]),
	] {
		let world = world();
		// In memory the account is the opposite of what the file will hold.
		world
			.store
			.set_disabled("alice", !disk_has)
			.expect("prepare");
		let path = format!("/api/v1/accounts/alice/{verb}");
		let (status, body, capture) = while_the_write_waits(&world, "POST", &path, WRITER, || {
			edit_on_disk(&world, "alice", "disabled", disk_has.into());
		})
		.await;
		assert_eq!(status, StatusCode::OK, "{verb}: {body}");
		assert_eq!(body["result"], result, "{verb}, file has {disk_has}");
		assert_eq!(capture.kinds(), kinds, "{verb}, file has {disk_has}");
		assert_eq!(disabled(&world, "alice"), verb == "disable");
	}
}
