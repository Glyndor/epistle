//! `epistle ban ... --json` against a real PostgreSQL. Runs only when
//! `DATABASE_URL` is set, like `tests/database_bans_cli.rs`, and says so
//! when it does not.

use serde_json::json;

use crate::harness::{env, epistle, json};

#[test]
fn ban_and_allow_list_changes() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|url| !url.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set, the ban results were not exercised");
		return;
	};
	let env = env(&format!("[database]\nurl = {url:?}\ntls = \"insecure\"\n"));
	let ban = |args: &[&str]| {
		let mut full = vec!["ban", "--config", env.config.as_str()];
		full.extend_from_slice(args);
		full.push("--json");
		json(&epistle(&full, b""))
	};
	let allow = json!({"result": "saved", "action": "allow add", "cidr": "198.51.100.0/24"});
	assert_eq!(ban(&["allow", "add", "198.51.100.0/24"]), (0, allow));
	assert_eq!(
		ban(&["allow", "add", "198.51.100.0/24"]),
		(0, json!({"result": "unchanged", "action": "allow add", "cidr": "198.51.100.0/24"}))
	);
	assert_eq!(
		ban(&["allow", "remove", "198.51.100.0/24"]),
		(0, json!({"result": "saved", "action": "allow remove", "cidr": "198.51.100.0/24"}))
	);
	let before = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let (code, mut added) = ban(&["add", "192.0.2.7", "--for", "1h"]);
	assert_eq!(code, 0);
	let until = added["until"].take().as_u64().expect("until");
	assert!((before + 3600..=before + 3700).contains(&until), "until {until}");
	assert_eq!(
		added,
		json!({"result": "saved", "action": "add", "target": "192.0.2.7", "until": null})
	);
	assert_eq!(
		ban(&["remove", "192.0.2.7"]),
		(
			0,
			json!({"result": "saved", "action": "remove", "target": "192.0.2.7", "bans": 1, "failures": 0})
		)
	);
}
