//! Exactly one active script: `onSuccessActivateScript` and
//! `onSuccessDeactivateScript` (RFC 9661 section 2.4).

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{app, call_as_alice, store, upload};
use super::tests::TOKEN;

async fn set(app: &axum::Router, args: Value) -> Value {
	let mut full = json!({"accountId": "alice"});
	full.as_object_mut()
		.expect("object")
		.extend(args.as_object().expect("object").clone());
	call_as_alice(app, "SieveScript/set", full).await
}

async fn blob(app: &axum::Router, script: &[u8]) -> String {
	upload(app, TOKEN.as_str(), "alice", script).await
}

/// Ids of the scripts the API reports active.
async fn active(app: &axum::Router) -> Vec<String> {
	let get = call_as_alice(app, "SieveScript/get", json!({"accountId": "alice"})).await;
	get[1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.filter(|script| script["isActive"] == true)
		.map(|script| script["id"].as_str().expect("id").to_string())
		.collect()
}

fn live(dir: &std::path::Path) -> Option<String> {
	std::fs::read_to_string(dir.join("accounts/alice/filter.sieve")).ok()
}

#[tokio::test]
async fn a_script_is_created_and_activated_in_one_call() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let old = store(dir.path(), "alice")
		.create("old", "keep;\r\n")
		.expect("old");
	store(dir.path(), "alice")
		.set_active(Some("old"))
		.expect("activate old");
	let blob = blob(&app, b"discard;\r\n").await;
	let response = set(
		&app,
		json!({"create": {"A": {"name": "new", "blobId": blob}}, "onSuccessActivateScript": "#A"}),
	)
	.await;
	let new_id = response[1]["created"]["A"]["id"]
		.as_str()
		.expect("id")
		.to_string();
	assert_eq!(response[1]["created"]["A"]["isActive"], true);
	assert_eq!(
		response[1]["updated"],
		json!({old.id.clone(): {"isActive": false}})
	);
	assert_eq!(active(&app).await, vec![new_id]);
	assert_eq!(
		store(dir.path(), "alice").active_name().as_deref(),
		Some("new")
	);
	assert_eq!(
		live(dir.path()).as_deref(),
		Some("discard;\r\n"),
		"delivery reads the new script"
	);
}

#[tokio::test]
async fn activating_an_existing_script_deactivates_the_previous_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let a = s.create("a", "keep;\r\n").expect("a");
	let b = s.create("b", "discard;\r\n").expect("b");
	set(&app, json!({"onSuccessActivateScript": a.id})).await;
	assert_eq!(active(&app).await, vec![a.id.clone()]);
	let response = set(&app, json!({"onSuccessActivateScript": b.id})).await;
	assert_eq!(response[1]["updated"][&b.id], json!({"isActive": true}));
	assert_eq!(response[1]["updated"][&a.id], json!({"isActive": false}));
	assert_eq!(active(&app).await, vec![b.id.clone()]);
	assert_eq!(live(dir.path()).as_deref(), Some("discard;\r\n"));
}

#[tokio::test]
async fn deactivating_leaves_no_active_script_and_no_filter() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let a = s.create("a", "keep;\r\n").expect("a");
	s.set_active(Some("a")).expect("activate");
	let response = set(&app, json!({"onSuccessDeactivateScript": true})).await;
	assert_eq!(
		response[1]["updated"],
		json!({a.id.clone(): {"isActive": false}})
	);
	assert_eq!(active(&app).await, Vec::<String>::new());
	assert_eq!(live(dir.path()), None);
	// Nothing active: nothing to report.
	let again = set(&app, json!({"onSuccessDeactivateScript": true})).await;
	assert_eq!(again[1]["updated"], json!({}));
	assert_eq!(again[1]["oldState"], again[1]["newState"]);
}

#[tokio::test]
async fn deactivation_is_processed_before_activation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let a = s.create("a", "keep;\r\n").expect("a");
	let b = s.create("b", "keep;\r\n").expect("b");
	s.set_active(Some("a")).expect("activate");
	let response = set(
		&app,
		json!({"onSuccessDeactivateScript": true, "onSuccessActivateScript": b.id}),
	)
	.await;
	assert_eq!(response[1]["updated"][&a.id], json!({"isActive": false}));
	assert_eq!(response[1]["updated"][&b.id], json!({"isActive": true}));
	assert_eq!(active(&app).await, vec![b.id]);
}

#[tokio::test]
async fn an_updated_script_that_is_activated_carries_both_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let a = store(dir.path(), "alice")
		.create("a", "keep;\r\n")
		.expect("a");
	let blob = blob(&app, b"discard;\r\n").await;
	let response = set(
		&app,
		json!({"update": {a.id.clone(): {"blobId": blob}}, "onSuccessActivateScript": a.id}),
	)
	.await;
	assert_eq!(
		response[1]["updated"][&a.id],
		json!({"blobId": format!("sieve-{}-2", a.id), "isActive": true})
	);
	assert_eq!(live(dir.path()).as_deref(), Some("discard;\r\n"));
}

#[tokio::test]
async fn activation_happens_only_if_everything_else_succeeded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let old = s.create("old", "keep;\r\n").expect("old");
	let target = s.create("target", "keep;\r\n").expect("target");
	s.set_active(Some("old")).expect("activate");
	let bad = blob(&app, b"if if").await;
	let response = set(
		&app,
		json!({
			"create": {"A": {"name": "broken", "blobId": bad}},
			"onSuccessActivateScript": target.id,
			"onSuccessDeactivateScript": true,
		}),
	)
	.await;
	assert!(response[1]["notCreated"]["A"].is_object());
	assert_eq!(response[1]["updated"], json!({}));
	assert_eq!(
		active(&app).await,
		vec![old.id],
		"the active script is untouched"
	);
	// A refused destroy counts the same way.
	let refused = set(
		&app,
		json!({"destroy": ["nope"], "onSuccessDeactivateScript": true}),
	)
	.await;
	assert_eq!(refused[1]["notDestroyed"]["nope"]["type"], "notFound");
	assert_eq!(active(&app).await.len(), 1);
}

#[tokio::test]
async fn an_id_that_names_no_script_is_ignored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let a = store(dir.path(), "alice")
		.create("a", "keep;\r\n")
		.expect("a");
	store(dir.path(), "alice")
		.set_active(Some("a"))
		.expect("activate");
	for id in ["nope", "#nope", "", "0123456789abcdef0123456789abcdef"] {
		let response = set(&app, json!({"onSuccessActivateScript": id})).await;
		assert_eq!(response[0], "SieveScript/set", "{id}");
		assert_eq!(response[1]["updated"], json!({}), "{id}");
	}
	assert_eq!(active(&app).await, vec![a.id], "the active script remains");
}

#[tokio::test]
async fn activating_the_active_script_again_changes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let a = store(dir.path(), "alice")
		.create("a", "keep;\r\n")
		.expect("a");
	store(dir.path(), "alice")
		.set_active(Some("a"))
		.expect("activate");
	let response = set(&app, json!({"onSuccessActivateScript": a.id})).await;
	assert_eq!(response[1]["updated"], json!({}));
	assert_eq!(response[1]["oldState"], response[1]["newState"]);
}

#[tokio::test]
async fn however_activation_is_asked_for_one_script_is_active() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let ids: Vec<String> = ["a", "b", "c"]
		.iter()
		.map(|name| {
			store(dir.path(), "alice")
				.create(name, "keep;\r\n")
				.expect("create")
				.id
		})
		.collect();
	for round in 0..9 {
		let id = &ids[round % 3];
		set(&app, json!({"onSuccessActivateScript": id})).await;
		assert_eq!(active(&app).await, vec![id.clone()], "round {round}");
		// ManageSieve agrees.
		let name = store(dir.path(), "alice").active_name();
		assert_eq!(name.as_deref(), Some(["a", "b", "c"][round % 3]));
	}
}

#[tokio::test]
async fn managesieve_activation_is_what_jmap_reports() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let s = store(dir.path(), "alice");
	let a = s.create("a", "keep;\r\n").expect("a");
	let b = s.create("b", "keep;\r\n").expect("b");
	s.set_active(Some("a")).expect("activate");
	assert_eq!(active(&app).await, vec![a.id.clone()]);
	s.set_active(Some("b")).expect("switch");
	assert_eq!(active(&app).await, vec![b.id]);
}

/// An installation from before the stricter name check: the active script is
/// `quarantine ` (a trailing space), which the store no longer lists.
fn legacy_active(dir: &std::path::Path) {
	let sieve = dir.join("accounts/alice/sieve");
	std::fs::create_dir_all(&sieve).expect("mkdir");
	std::fs::write(sieve.join("quarantine .sieve"), "discard;\r\n").expect("script");
	std::fs::write(sieve.join(".active"), "quarantine ").expect("marker");
	std::fs::write(dir.join("accounts/alice/filter.sieve"), "discard;\r\n").expect("live");
}

#[tokio::test]
async fn deactivating_switches_off_an_active_script_whose_name_is_no_longer_valid() {
	let dir = tempfile::tempdir().expect("tempdir");
	legacy_active(dir.path());
	let app = app(dir.path());
	let response = set(&app, json!({"onSuccessDeactivateScript": true})).await;
	assert_eq!(response[0], "SieveScript/set", "{response}");
	assert!(
		live(dir.path()).is_none(),
		"the hidden filter is still running"
	);
	assert!(
		!dir.path().join("accounts/alice/sieve/.active").exists()
			|| std::fs::read_to_string(dir.path().join("accounts/alice/sieve/.active"))
				.expect("marker")
				.is_empty()
	);
	assert_ne!(
		response[1]["oldState"], response[1]["newState"],
		"it was a change"
	);
}

#[tokio::test]
async fn activating_another_script_replaces_a_hidden_active_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	legacy_active(dir.path());
	let app = app(dir.path());
	let blob = blob(&app, b"keep;\r\n").await;
	let response = set(
		&app,
		json!({"create": {"A": {"name": "new", "blobId": blob}}, "onSuccessActivateScript": "#A"}),
	)
	.await;
	assert_eq!(response[1]["notCreated"], json!({}), "{response}");
	assert_eq!(live(dir.path()).as_deref(), Some("keep;\r\n"));
	assert_eq!(active(&app).await.len(), 1);
}

#[tokio::test]
async fn the_log_says_when_the_active_script_is_one_left_out() {
	let dir = tempfile::tempdir().expect("tempdir");
	legacy_active(dir.path());
	let s = store(dir.path(), "alice");
	let events = crate::cli::tracing_capture::run_with_capture(|| {
		s.list().expect("list");
	});
	let said = events
		.iter()
		.find(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("are not listed"))
		})
		.expect("said");
	assert_eq!(
		said.fields.get("active_left_out").map(String::as_str),
		Some("true"),
		"{said:?}"
	);
}

#[tokio::test]
async fn an_unknown_activation_id_leaves_a_hidden_active_script_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	legacy_active(dir.path());
	let app = app(dir.path());
	set(&app, json!({"onSuccessActivateScript": "no-such-id"})).await;
	assert_eq!(live(dir.path()).as_deref(), Some("discard;\r\n"));
}
