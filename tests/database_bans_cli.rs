//! `epistle ban` driven as the real binary against a live PostgreSQL. Runs only
//! when `DATABASE_URL` is set, like `tests/database_bans.rs`. Each step asserts
//! the exact line printed and the effect the running server would see (a fresh
//! ban-store check on the same database), which is how a CLI change reaches the
//! server without a restart.

use std::process::{Command, Output};

use epistle::antispam::bans::{BanStore, PgBanStore, subject_pair};
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
	let until_text = line
		.trim()
		.strip_prefix(&format!("banned {ip} until "))
		.unwrap_or_else(|| panic!("unexpected output {line:?}"));
	let json = h.ban(&["list", "--json"]);
	let rows: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("json");
	let row = rows
		.as_array()
		.expect("array")
		.iter()
		.find(|r| r["subject"] == format!("ip:{ip}"))
		.expect("ban in json");
	let until = row["until"].as_u64().expect("epoch");
	assert_eq!(
		(row["reason"].as_str(), row["until"].as_u64()),
		(Some("manual ban"), Some(until))
	);
	assert!(
		(before + 7200..=now() + 7200).contains(&until),
		"until={until}"
	);
	assert_eq!(
		until_text,
		epistle::clock::rfc3339(until),
		"the text shows the same instant the JSON keeps as an epoch"
	);
	assert!(h.banned(&ip).await, "the ban must apply without a restart");

	let listed = h.ban(&["list"]);
	assert!(
		stdout(&listed)
			.lines()
			.any(|l| l == format!("ip:{ip}\tuntil={until_text}\tmanual ban")),
		"{}",
		stdout(&listed)
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
	let until_text = stdout(&added)
		.trim()
		.strip_prefix(&format!("banned {net} until "))
		.expect("prefix")
		.to_string();
	let json = h.ban(&["list", "--json"]);
	let rows: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("json");
	let row = rows
		.as_array()
		.expect("array")
		.iter()
		.find(|r| r["subject"] == format!("cidr:{net}"))
		.expect("ban in json");
	let until = row["until"].as_u64().expect("epoch");
	assert!(
		(before + 86_400..=now() + 86_400).contains(&until),
		"until={until}"
	);
	assert_eq!(
		until_text,
		epistle::clock::rfc3339(until),
		"the text shows the same instant the JSON keeps as an epoch"
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

/// Record `times` failures on `subject`, enough for the default policy to ban it.
async fn ban_with_failures(store: &PgBanStore, subject: &str, times: usize) {
	for _ in 0..times {
		store.record_failure(subject, "imap", now()).await;
	}
	assert!(store.is_banned(subject, now()).await.is_some());
}

#[tokio::test]
async fn remove_lifts_a_pair_ban_in_the_form_list_prints_it() {
	let Some(h) = Harness::new().await else {
		return;
	};
	let block = fresh_block();
	let login = format!("pair-{}", uuid::Uuid::now_v7().simple());
	let client: std::net::IpAddr = format!("{block}::5").parse().expect("ip");
	let pair = subject_pair(&login, Some(client));
	assert_eq!(pair, format!("pair:{login}|{block}::"));

	ban_with_failures(&h.store, &pair, 5).await;
	let listed = stdout(&h.ban(&["list"]));
	assert!(
		listed.lines().any(|l| l.starts_with(&format!("{pair}\t"))),
		"{listed}"
	);
	let removed = h.ban(&["remove", &pair]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert_eq!(
		stdout(&removed),
		format!("unbanned {pair} (1 bans, 5 failures cleared)\n")
	);
	assert!(h.store.is_banned(&pair, now()).await.is_none());

	// The same pair named by its parts, from another address in the same /64.
	ban_with_failures(&h.store, &pair, 5).await;
	let other = format!("{block}::9");
	let removed = h.ban(&["remove", "--account", &login, "--ip", &other]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert_eq!(
		stdout(&removed),
		format!("unbanned {pair} (1 bans, 5 failures cleared)\n")
	);
	assert!(h.store.is_banned(&pair, now()).await.is_none());

	let again = h.ban(&["remove", &pair]);
	assert_eq!(again.status.code(), Some(1));
	assert!(
		stderr(&again).contains(&format!("{pair} has no ban or failure record")),
		"{}",
		stderr(&again)
	);
}

#[tokio::test]
async fn lifting_a_pair_leaves_the_address_and_the_account_banned() {
	let Some(h) = Harness::new().await else {
		return;
	};
	let block = fresh_block();
	let ip = format!("{block}::5");
	let login = format!("pair-{}", uuid::Uuid::now_v7().simple());
	let pair = subject_pair(&login, Some(ip.parse().expect("ip")));
	let account = format!("account:{login}");
	ban_with_failures(&h.store, &pair, 5).await;
	ban_with_failures(&h.store, &account, 20).await;
	assert!(h.ban(&["add", &ip, "--for", "1h"]).status.success());

	let removed = h.ban(&["remove", &pair]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert!(h.store.is_banned(&pair, now()).await.is_none());
	assert!(h.banned(&ip).await, "the address ban must stay");
	assert!(
		h.store.is_banned(&account, now()).await.is_some(),
		"the account ban must stay"
	);

	let removed = h.ban(&["remove", &account]);
	assert!(removed.status.success(), "{}", stderr(&removed));
	assert!(h.store.is_banned(&account, now()).await.is_none());
	h.ban(&["remove", &ip]);
}
