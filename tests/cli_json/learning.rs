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
			"unlearned": 0, "repeated": 0, "refused": 0, "throttled": 0, "entries": 0,
			"token_rows": 0, "unrecorded": 0, "corpus_spam": 0, "corpus_ham": 0,
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

	// A reset keeps the switch: the account that was switched off to stop it
	// teaching is still off afterwards.
	learning(&["disable", &name]);
	learning(&["reset", &name, "--yes"]);
	let (_, status) = json(&learning(&["status", &name]));
	assert_eq!(
		status["enabled"],
		json!(false),
		"reset must not switch learning back on"
	);
	learning(&["enable", &name]);

	let ghost = learning(&["enable", "no-such-account"]);
	assert_eq!(
		ghost.status.code(),
		Some(2),
		"an unknown account is refused"
	);
	assert!(ghost.stdout.is_empty());
}

/// The ghost account and the dry run: what must not be written when the
/// command only previews, or when the name is not an account.
#[test]
fn dry_runs_write_nothing_and_unknown_accounts_are_refused() {
	use epistle::antispam::corpus::BayesStore;

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
	// Something to lose: one message learned as spam, through the library.
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	runtime.block_on(async {
		let pool = epistle::db::connect(&url, epistle::config::DatabaseTls::Insecure, 2, None)
			.await
			.expect("connect");
		let mut key = [0u8; 32];
		key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
		key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
		let store = BayesStore::with_key(pool, key);
		store
			.learn(
				&name,
				b"Subject: pills\r\n\r\ncheap pills discount now\r\n",
				true,
			)
			.await
			.expect("learn");
	});
	for args in [
		vec!["reset", &name, "--dry-run", "--yes"],
		vec!["reset", &name, "--dry-run"],
	] {
		let (code, preview) = json(&learning(&args));
		assert_eq!(code, 0, "{args:?}");
		assert_eq!(preview["result"], json!("dry-run"), "{args:?}");
		let (_, status) = json(&learning(&["status", &name]));
		assert_eq!(
			(status["entries"].clone(), status["corpus_spam"].clone()),
			(json!(1), json!(1)),
			"{args:?} must not drop the corpus"
		);
	}
	let (_, disabled) = json(&learning(&["disable", &name, "--dry-run"]));
	assert_eq!(disabled["result"], json!("dry-run"));
	let (_, status) = json(&learning(&["status", &name]));
	assert_eq!(status["enabled"], json!(true), "a dry run does not switch");

	for args in [
		vec!["disable", "no-such-account"],
		vec!["reset", "no-such-account", "--yes"],
		vec!["reset", "no-such-account", "--dry-run"],
	] {
		let output = learning(&args);
		assert_eq!(output.status.code(), Some(2), "{args:?}");
		assert!(output.stdout.is_empty(), "{args:?} printed on stdout");
	}
	let (_, before) = json(&learning(&["status", &name]));
	let rows = before["token_rows"].clone();
	assert!(
		rows.as_i64().is_some_and(|n| n > 0),
		"the lesson wrote rows"
	);
	let (code, done) = json(&learning(&["reset", &name, "--yes"]));
	assert_eq!(code, 0);
	assert_eq!(
		done["tokens"], rows,
		"the report says how many token rows the reset dropped"
	);
	let (_, status) = json(&learning(&["status", &name]));
	assert_eq!(
		status["corpus_spam"],
		json!(0),
		"the real reset drops the corpus"
	);
}

/// A listing that stops at the cap says so on stderr, where a list of exactly
/// that many accounts cannot be taken for the whole.
#[test]
fn a_listing_cut_at_the_cap_says_so_on_stderr() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set, the learning results were not exercised");
		return;
	};
	let env = env(&format!("[database]\nurl = {url:?}\ntls = \"insecure\"\n"));
	let prefix = format!("zzzzcut-{}-", uuid::Uuid::now_v7().simple());
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let pool = runtime.block_on(async {
		let pool = epistle::db::connect(&url, epistle::config::DatabaseTls::Insecure, 2, None)
			.await
			.expect("connect");
		// Named to sort after every real account, so the rows the cap cuts
		// are these and not another test's.
		sqlx::query(
			"INSERT INTO bayes_learning (scope) \
			 SELECT $1 || n FROM generate_series(1, 10000) AS n",
		)
		.bind(&prefix)
		.execute(&pool)
		.await
		.expect("seed");
		pool
	});
	let output = epistle(
		&[
			"learning",
			"--config",
			env.config.as_str(),
			"status",
			"--json",
		],
		b"",
	);
	runtime.block_on(async {
		sqlx::query("DELETE FROM bayes_learning WHERE scope LIKE $1 || '%'")
			.bind(&prefix)
			.execute(&pool)
			.await
			.expect("cleanup");
	});
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("the list stops at 10000 accounts"),
		"stderr: {stderr}"
	);
	let (code, rows) = json(&output);
	assert_eq!(code, 0);
	assert_eq!(rows.as_array().map(Vec::len), Some(10_000));
}
