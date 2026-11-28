//! A suspended account through SCIM: a key confined to domains does not resume
//! it, remove it or change its addresses, and an unconfined key does all three.

use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::api::ApiState;
use crate::api::audit::tests::base::{audit_events, run_with_capture};
use crate::directory_store::AccountStore;
use crate::test_support::fixtures;

use super::base::{CONFIGURED_TOKEN, app};
use super::tenants::{call, tenant_key, tenants, unconfined_key};

/// The address `alice` is known by first.
pub(super) const MAIN: &str = "alice@a.test";
/// Her second address.
pub(super) const OTHER: &str = "alice.other@a.test";
/// An address of the same tenant nobody holds.
const FREE: &str = "alice.new@a.test";

/// What a refusal says, by what the request would have done.
const RESUMING: &str = "resuming an account is for a key";
const REMOVING: &str = "removing a suspended account is for a key";
const READDRESSING: &str = "changing the addresses of a suspended account is for a key";

pub(super) struct World {
	pub(super) dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<AccountStore>,
}

impl World {
	/// The account file as it is on disk.
	pub(super) fn file(&self) -> String {
		std::fs::read_to_string(self.store.store_path()).expect("account file")
	}

	/// The one message in the mailbox of `alice`.
	pub(super) fn mail(&self) -> std::path::PathBuf {
		self.dir.path().join("accounts/alice/new/1.eml")
	}
}

/// The two tenants, with `alice` holding two addresses and one message, and
/// suspended when `suspended` says so.
pub(super) fn world(suspended: bool) -> World {
	let (dir, state, store) = tenants();
	store.add_address("alice", OTHER).expect("second address");
	store.set_disabled("alice", suspended).expect("state");
	let world = World { dir, state, store };
	std::fs::create_dir_all(world.mail().parent().expect("parent")).expect("mailbox");
	std::fs::write(world.mail(), "Subject: kept\r\n\r\n").expect("message");
	world
}

fn put(active: bool, emails: &[&str]) -> Value {
	let emails: Vec<Value> = emails.iter().map(|value| json!({"value": value})).collect();
	json!({"userName": "alice", "active": active, "emails": emails})
}

fn patch(operations: &[(&str, Value)]) -> Value {
	let operations: Vec<Value> = operations
		.iter()
		.map(|(path, value)| json!({"op": "replace", "path": path, "value": value}))
		.collect();
	json!({"Operations": operations})
}

/// One request on `alice`.
pub(super) struct Request {
	pub(super) what: &'static str,
	pub(super) method: &'static str,
	pub(super) body: Option<Value>,
}

fn request(what: &'static str, method: &'static str, body: Value) -> Request {
	Request {
		what,
		method,
		body: Some(body),
	}
}

/// Every request that would undo a suspension, with what its refusal says.
pub(super) fn undoing() -> Vec<(Request, &'static str)> {
	let resumes = [
		request("PUT resumes", "PUT", put(true, &[MAIN, OTHER])),
		request("PUT resumes naming no address", "PUT", put(true, &[])),
		request("PATCH resumes", "PATCH", patch(&[("active", json!(true))])),
		request(
			"PATCH resumes among other changes",
			"PATCH",
			patch(&[
				("password", json!(fixtures::second_password())),
				("active", json!(false)),
				("displayName", json!("Alice")),
				("active", json!(true)),
			]),
		),
	];
	let readdresses = [
		request("PUT replaces an address", "PUT", put(false, &[MAIN, FREE])),
		request(
			"PUT adds an address",
			"PUT",
			put(false, &[MAIN, OTHER, FREE]),
		),
		request("PUT drops an address", "PUT", put(false, &[MAIN])),
		request(
			"PUT changes the first address",
			"PUT",
			put(false, &[OTHER, MAIN]),
		),
	];
	let removes = Request {
		what: "DELETE",
		method: "DELETE",
		body: None,
	};
	resumes
		.into_iter()
		.map(|one| (one, RESUMING))
		.chain(readdresses.into_iter().map(|one| (one, READDRESSING)))
		.chain([(removes, REMOVING)])
		.collect()
}

/// Requests that leave a suspended account suspended, with its addresses.
pub(super) fn leaving() -> Vec<Request> {
	let password = fixtures::second_password();
	vec![
		request("PUT as it is", "PUT", put(false, &[MAIN, OTHER])),
		request(
			"PUT with the same addresses spelled otherwise",
			"PUT",
			put(
				false,
				&["ALICE@A.TEST", "alice@a.test", "Alice.Other@a.test"],
			),
		),
		request("PUT naming no address", "PUT", put(false, &[])),
		request(
			"PUT with a password and a name",
			"PUT",
			json!({
				"userName": "alice",
				"active": false,
				"password": password,
				"displayName": "Alice",
			}),
		),
		request(
			"PATCH suspends",
			"PATCH",
			patch(&[("active", json!(false))]),
		),
		request(
			"PATCH password",
			"PATCH",
			patch(&[("password", json!(password))]),
		),
		request(
			"PATCH name",
			"PATCH",
			patch(&[("displayName", json!("Alice"))]),
		),
		request(
			"PATCH resumes and then suspends",
			"PATCH",
			patch(&[("active", json!(true)), ("active", json!(false))]),
		),
	]
}

/// Send `request` with `key`: the status, the body and the audit events.
fn send_captured(world: &World, key: &str, request: &Request) -> (StatusCode, Value, Vec<String>) {
	let app = app(world.state.clone());
	let mut answer = None;
	let events = run_with_capture(async {
		answer = Some(
			call(
				&app,
				request.method,
				"/scim/v2/Users/alice",
				key,
				request.body.as_ref(),
			)
			.await,
		);
	});
	let (status, body) = answer.expect("an answer");
	let kinds = audit_events(&events)
		.iter()
		.map(|event| event.fields.get("event").cloned().unwrap_or_default())
		.collect();
	(status, body, kinds)
}

/// A refused request answers `status` with `says`, writes nothing and records
/// nothing. The differences, if any.
pub(super) fn refusal_differences(
	world: &World,
	request: &Request,
	before: &str,
	answer: (StatusCode, Value, Vec<String>),
	status: StatusCode,
	says: &str,
) -> Vec<String> {
	let (found, body, kinds) = answer;
	let what = request.what;
	let mut wrong = Vec::new();
	let detail = body["detail"].as_str().unwrap_or_default();
	if found != status || !detail.contains(says) {
		wrong.push(format!("{what}: answered {found} {body}"));
	}
	if found == status && body["status"] != status.as_str() {
		wrong.push(format!("{what}: not a SCIM error: {body}"));
	}
	if world.file() != before {
		wrong.push(format!("{what}: the account file was written"));
	}
	if !world.mail().exists() {
		wrong.push(format!("{what}: the mail is gone"));
	}
	if !kinds.is_empty() {
		wrong.push(format!("{what}: recorded {kinds:?}"));
	}
	wrong
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confined_key_does_not_undo_a_suspension() {
	// Every request is tried before judging, so a failure names all that differ.
	let mut wrong = Vec::new();
	for (request, says) in undoing() {
		let world = world(true);
		let before = world.file();
		let answer = send_captured(&world, tenant_key(), &request);
		wrong.extend(refusal_differences(
			&world,
			&request,
			&before,
			answer,
			StatusCode::FORBIDDEN,
			says,
		));
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confined_key_makes_the_other_changes_of_a_suspended_account() {
	let mut wrong = Vec::new();
	for request in leaving() {
		let world = world(true);
		let (status, body, _) = send_captured(&world, tenant_key(), &request);
		let kept = world.store.dynamic("alice").expect("alice");
		if status != StatusCode::OK || !kept.disabled || kept.addresses != [MAIN, OTHER] {
			wrong.push(format!("{}: {status} {body}", request.what));
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confined_key_changes_an_active_account_as_before() {
	let mut wrong = Vec::new();
	for (request, _) in undoing() {
		let world = world(false);
		let before = world.file();
		let (status, body, _) = send_captured(&world, tenant_key(), &request);
		// Resuming an active account may write the file as it was; every other
		// request changes it.
		let written = request.what.contains("resumes") || world.file() != before;
		if !status.is_success() || !written {
			wrong.push(format!("{}: {status} {body}", request.what));
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfined_key_undoes_a_suspension_as_before() {
	let mut wrong = Vec::new();
	for key in [unconfined_key(), CONFIGURED_TOKEN.as_str()] {
		for (request, _) in undoing() {
			let world = world(true);
			let before = world.file();
			let (status, body, _) = send_captured(&world, key, &request);
			if !status.is_success() || world.file() == before {
				wrong.push(format!("{}: {status} {body}", request.what));
			}
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}
