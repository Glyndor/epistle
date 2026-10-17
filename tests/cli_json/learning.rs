//! `epistle learning ... --json` against a real PostgreSQL. Runs only when
//! `DATABASE_URL` is set, like `tests/cli_json/ban.rs`, and says so when it
//! does not. The refusals that need no database run always.

use serde_json::json;

use crate::harness::{add_account, env, epistle, json};

fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL")
		.ok()
		.filter(|url| !url.is_empty())
}

#[test]
fn without_a_database_every_action_is_refused_by_policy() {
	let env = env("");
	for args in [
		&["status"][..],
		&["enable", "bob"],
		&["disable", "bob"],
		&["reset", "bob", "--yes"],
	] {
		let mut full = vec!["learning", "--config", env.config.as_str()];
		full.extend_from_slice(args);
		full.push("--json");
		let output = epistle(&full, b"");
		assert_eq!(output.status.code(), Some(3), "{args:?}");
		assert!(output.stdout.is_empty(), "{args:?} printed on stdout");
	}
}

#[test]
fn status_switch_and_reset() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set, the learning results were not exercised");
		return;
	};
	let env = env(&format!("[database]\nurl = {url:?}\ntls = \"insecure\"\n"));
	let name = format!("lrn{}", &uuid::Uuid::now_v7().simple().to_string()[20..]);
	add_account(&env, &name);
	let learning = |args: &[&str]| {
		let mut full = vec!["learning", "--config", env.config.as_str()];
		full.extend_from_slice(args);
		full.push("--json");
		epistle(&full, b"")
	};
	let (code, status) = json(&learning(&["status", &name]));
	assert_eq!(code, 0);
	assert_eq!(
		status,
		json!({
			"account": name, "enabled": true, "spam_learned": 0, "ham_learned": 0,
			"unlearned": 0, "repeated": 0, "refused": 0, "entries": 0,
			"corpus_spam": 0, "corpus_ham": 0,
		}),
		"an account that never learned reads as on with zero counters"
	);
	let off = json!({"result": "saved", "action": "disable", "account": name, "enabled": false});
	assert_eq!(json(&learning(&["disable", &name])), (0, off));
	let again =
		json!({"result": "unchanged", "action": "disable", "account": name, "enabled": false});
	assert_eq!(json(&learning(&["disable", &name])), (0, again));
	let (_, status) = json(&learning(&["status", &name]));
	assert_eq!(status["enabled"], json!(false));
	let (_, all) = json(&learning(&["status"]));
	assert!(
		all.as_array()
			.expect("an array")
			.iter()
			.any(|row| row["account"] == json!(name) && row["enabled"] == json!(false)),
		"the switched-off account is listed"
	);
	let (code, preview) = json(&learning(&["enable", &name, "--dry-run"]));
	assert_eq!(code, 0);
	assert_eq!(preview["result"], json!("dry-run"));
	assert_eq!(preview["diff"], json!("learning: off -> on"));
	let (_, status) = json(&learning(&["status", &name]));
	assert_eq!(status["enabled"], json!(false), "a dry run writes nothing");
	let on = json!({"result": "saved", "action": "enable", "account": name, "enabled": true});
	assert_eq!(json(&learning(&["enable", &name])), (0, on));

	let refused = learning(&["reset", &name]);
	assert_eq!(
		refused.status.code(),
		Some(2),
		"reset needs --yes off a terminal"
	);
	assert!(refused.stdout.is_empty());
	let done = json!({"result": "saved", "action": "reset", "account": name, "tokens": 0});
	assert_eq!(json(&learning(&["reset", &name, "--yes"])), (0, done));

	let ghost = learning(&["enable", "no-such-account"]);
	assert_eq!(
		ghost.status.code(),
		Some(2),
		"an unknown account is refused"
	);
	assert!(ghost.stdout.is_empty());
}
