//! `epistle ban` driven as the real binary against a live PostgreSQL. Runs only
//! when `DATABASE_URL` is set, like `tests/database_bans.rs`. Each step asserts
//! the exact line printed and the effect the running server would see (a fresh
//! ban-store check on the same database), which is how a CLI change reaches the
//! server without a restart.

use std::process::{Command, Output};

use epistle::antispam::bans::{BanStore, PgBanStore};
use epistle::config::DatabaseTls;

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// A private documentation-range `/64` for this test, as its first four groups.
fn fresh_block() -> String {
	let bytes = uuid::Uuid::now_v7().into_bytes();
	format!(
		"2001:db8:{:x}:{:x}",
		u16::from_be_bytes([bytes[12], bytes[13]]),
		u16::from_be_bytes([bytes[14], bytes[15]])
	)
}

struct Harness {
	store: PgBanStore,
	config: tempfile::NamedTempFile,
	_data: tempfile::TempDir,
}

impl Harness {
	async fn new() -> Option<Self> {
		let url = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty());
		let Some(url) = url else {
			eprintln!("skipping: DATABASE_URL not set");
			return None;
		};
		let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
			.await
			.expect("connect and migrate");
		let data = tempfile::tempdir().expect("data dir");
		let config = tempfile::NamedTempFile::new().expect("config");
		std::fs::write(
			config.path(),
			format!(
				"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n\
				 [database]\nurl = {url:?}\ntls = \"insecure\"\n",
				data.path()
			),
		)
		.expect("write config");
		Some(Self {
			store: PgBanStore::new(pool, None),
			config,
			_data: data,
		})
	}

	fn ban(&self, args: &[&str]) -> Output {
		Command::new(env!("CARGO_BIN_EXE_epistle"))
			.arg("ban")
			.args(args)
			.arg("--config")
			.arg(self.config.path())
			.env("NO_COLOR", "1")
			.output()
			.expect("run epistle")
	}

	async fn banned(&self, ip: &str) -> bool {
		self.store
			.is_banned(&format!("ip:{ip}"), now())
			.await
			.is_some()
	}
}

fn stdout(output: &Output) -> String {
	String::from_utf8(output.stdout.clone()).expect("utf8")
}

fn stderr(output: &Output) -> String {
	String::from_utf8(output.stderr.clone()).expect("utf8")
}

#[tokio::test]
async fn add_list_and_remove_a_ban_reach_the_server_immediately() {
	let Some(h) = Harness::new().await else {
		return;
	};
	let ip = format!("{}::5", fresh_block());
	assert!(!h.banned(&ip).await);

	let before = now();
	let added = h.ban(&["add", &ip, "--for", "2h"]);
	assert!(added.status.success(), "{}", stderr(&added));
	let line = stdout(&added);
	let until: u64 = line
		.trim()
		.strip_prefix(&format!("banned {ip} until "))
		.unwrap_or_else(|| panic!("unexpected output {line:?}"))
		.parse()
		.expect("epoch");
	assert!(
		(before + 7200..=now() + 7200).contains(&until),
		"until={until}"
	);
	assert!(h.banned(&ip).await, "the ban must apply without a restart");

	let listed = h.ban(&["list"]);
	assert!(
		stdout(&listed)
			.lines()
			.any(|l| l == format!("ip:{ip}\tuntil={until}\tmanual ban")),
		"{}",
		stdout(&listed)
	);
	let json = h.ban(&["list", "--json"]);
	let rows: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("json");
	let row = rows
		.as_array()
		.expect("array")
		.iter()
		.find(|r| r["subject"] == format!("ip:{ip}"))
		.expect("ban in json");
	assert_eq!(
		(row["reason"].as_str(), row["until"].as_u64()),
		(Some("manual ban"), Some(until))
	);

	let removed = h.ban(&["remove", &ip]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert_eq!(
		stdout(&removed),
		format!("unbanned {ip} (1 bans, 0 failures cleared)\n")
	);
	assert!(
		!h.banned(&ip).await,
		"the unban must apply without a restart"
	);

	let again = h.ban(&["remove", &ip]);
	assert_eq!(again.status.code(), Some(1));
	assert!(
		stderr(&again).contains(&format!("{ip} has no ban or failure record")),
		"{}",
		stderr(&again)
	);
}

#[tokio::test]
async fn a_network_ban_defaults_to_24_hours_and_remove_takes_the_network() {
	let Some(h) = Harness::new().await else {
		return;
	};
	let block = fresh_block();
	let net = format!("{block}::/64");
	let before = now();
	let added = h.ban(&["add", &net]);
	assert!(added.status.success(), "{}", stderr(&added));
	let until: u64 = stdout(&added)
		.trim()
		.strip_prefix(&format!("banned {net} until "))
		.expect("prefix")
		.parse()
		.expect("epoch");
	assert!(
		(before + 86_400..=now() + 86_400).contains(&until),
		"until={until}"
	);
	assert!(h.banned(&format!("{block}::abcd")).await);

	let removed = h.ban(&["remove", &net]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert!(!h.banned(&format!("{block}::abcd")).await);
}

#[tokio::test]
async fn the_allow_list_actions_and_their_effect_on_a_ban() {
	let Some(h) = Harness::new().await else {
		return;
	};
	let block = fresh_block();
	let net = format!("{block}::/120");
	let ip = format!("{block}::7");

	let added = h.ban(&["allow", "add", &net]);
	assert!(added.status.success(), "{}", stderr(&added));
	assert_eq!(stdout(&added), format!("allowed {net}\n"));
	assert_eq!(
		stdout(&h.ban(&["allow", "add", &net])),
		format!("already allowed {net}\n")
	);
	assert!(stdout(&h.ban(&["allow", "list"])).lines().any(|l| l == net));
	let json = h.ban(&["allow", "list", "--json"]);
	let entries: Vec<String> = serde_json::from_str(&stdout(&json)).expect("json");
	assert!(entries.contains(&net));

	// A manual ban on an allow-listed address is refused, not silently useless.
	let refused = h.ban(&["add", &ip]);
	assert_eq!(refused.status.code(), Some(1));
	assert!(
		stderr(&refused).contains(&format!("{ip} is on the allow list")),
		"{}",
		stderr(&refused)
	);
	assert!(!h.banned(&ip).await);

	let removed = h.ban(&["allow", "remove", &net]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert_eq!(
		stdout(&removed),
		format!("removed {net} from the allow list\n")
	);
	let missing = h.ban(&["allow", "remove", &net]);
	assert_eq!(missing.status.code(), Some(1));
	assert!(stderr(&missing).contains(&format!("{net} is not on the allow list")));
	assert!(h.ban(&["add", &ip, "--for", "1h"]).status.success());
	assert!(h.banned(&ip).await);
	h.ban(&["remove", &ip]);
}
