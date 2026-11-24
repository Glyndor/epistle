//! `epistle archive purge` and `archive restore` against archives written the
//! way an expunge writes them: what `--older-than-days` takes, what it keeps,
//! and that nothing is deleted without `--yes` off a terminal.

use serde_json::Value;
use uuid::Uuid;

use crate::harness::{Env, add_account, env, epistle};

const DAY: u64 = 86_400;

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

/// An archive entry for `account` deleted `age_days` days ago, with a body.
fn archived(env: &Env, account: &str, age_days: u64) -> Uuid {
	let id = Uuid::now_v7();
	let dir = env
		.data_dir()
		.join("accounts")
		.join(account)
		.join(".archive");
	std::fs::create_dir_all(&dir).expect("archive dir");
	let when = now() - age_days * DAY;
	std::fs::write(
		dir.join(format!("{id}.deleted")),
		format!("{when}\nINBOX\n"),
	)
	.expect("sidecar");
	std::fs::write(
		dir.join(format!("{id}.eml")),
		format!("From: a@example.org\r\nSubject: {id}\r\n\r\nbody\r\n"),
	)
	.expect("body");
	id
}

fn run(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = vec!["archive"];
	full.extend_from_slice(args);
	full.extend_from_slice(&["--config", &env.config]);
	epistle(&full, b"")
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The ids `archive list` shows for `account`.
fn listed(env: &Env, account: &str) -> Vec<String> {
	let output = run(env, &["list", account, "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let rows: Value = serde_json::from_slice(&output.stdout).expect("a JSON array");
	let mut ids: Vec<String> = rows
		.as_array()
		.expect("array")
		.iter()
		.map(|row| row["id"].as_str().expect("id").to_string())
		.collect();
	ids.sort();
	ids
}

/// The message files of `account` outside its archive.
fn delivered_bodies(env: &Env, account: &str) -> usize {
	fn walk(dir: &std::path::Path, count: &mut usize) {
		for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
			let path = entry.path();
			if path.is_dir() {
				if path.file_name().is_some_and(|name| name != ".archive") {
					walk(&path, count);
				}
			} else if path.extension().is_some_and(|ext| ext == "eml") {
				*count += 1;
			}
		}
	}
	let mut count = 0;
	walk(&env.data_dir().join("accounts").join(account), &mut count);
	count
}

fn sorted(ids: &[Uuid]) -> Vec<String> {
	let mut ids: Vec<String> = ids.iter().map(Uuid::to_string).collect();
	ids.sort();
	ids
}

#[test]
fn older_than_days_purges_what_is_older_and_keeps_the_rest() {
	let env = env("");
	add_account(&env, "alice");
	let (recent, old, older) = (
		archived(&env, "alice", 10),
		archived(&env, "alice", 40),
		archived(&env, "alice", 100),
	);
	assert_eq!(listed(&env, "alice"), sorted(&[recent, old, older]));

	let output = run(
		&env,
		&[
			"purge",
			"alice",
			"--older-than-days",
			"30",
			"--yes",
			"--json",
		],
	);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	assert_eq!(result["purged"], 2, "{result}");
	assert_eq!(listed(&env, "alice"), sorted(&[recent]));
	let archive = env.data_dir().join("accounts/alice/.archive");
	assert!(archive.join(format!("{recent}.eml")).exists());
	assert!(!archive.join(format!("{old}.eml")).exists());
	assert!(!archive.join(format!("{older}.deleted")).exists());

	// Nothing is old enough: the command says so and keeps the entry.
	let output = run(
		&env,
		&[
			"purge",
			"alice",
			"--older-than-days",
			"30",
			"--yes",
			"--json",
		],
	);
	assert_eq!(output.status.code(), Some(0));
	let result: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	assert_eq!(result["purged"], 0);
	assert_eq!(listed(&env, "alice"), sorted(&[recent]));
}

#[test]
fn without_older_than_days_every_entry_goes() {
	let env = env("");
	add_account(&env, "alice");
	archived(&env, "alice", 1);
	archived(&env, "alice", 200);
	let output = run(&env, &["purge", "alice", "--yes"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	assert!(listed(&env, "alice").is_empty());
}

#[test]
fn a_purge_of_one_account_leaves_another_accounts_archive_alone() {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	archived(&env, "alice", 90);
	let kept = archived(&env, "bob", 90);
	let output = run(&env, &["purge", "alice", "--yes"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	assert_eq!(listed(&env, "bob"), sorted(&[kept]));
}

#[test]
fn a_purge_off_a_terminal_without_yes_is_refused_and_removes_nothing() {
	let env = env("");
	add_account(&env, "alice");
	let ids = [archived(&env, "alice", 90), archived(&env, "alice", 5)];
	for extra in [&[][..], &["--older-than-days", "1"][..]] {
		let mut args = vec!["purge", "alice"];
		args.extend_from_slice(extra);
		let output = run(&env, &args);
		assert_eq!(output.status.code(), Some(2), "{extra:?}");
		assert!(output.stdout.is_empty(), "{extra:?}");
		assert!(
			stderr(&output).contains("archive purge was not confirmed"),
			"{}",
			stderr(&output)
		);
		assert_eq!(listed(&env, "alice"), sorted(&ids), "{extra:?}");
	}
}

#[test]
fn a_number_of_days_that_is_not_one_is_refused_before_anything_is_removed() {
	let env = env("");
	add_account(&env, "alice");
	let ids = [archived(&env, "alice", 90)];
	for days in ["abc", "-3", "1.5", ""] {
		let output = run(
			&env,
			&["purge", "alice", "--older-than-days", days, "--yes"],
		);
		assert_eq!(output.status.code(), Some(2), "{days:?}");
		assert!(output.stdout.is_empty(), "{days:?}");
		assert_eq!(listed(&env, "alice"), sorted(&ids), "{days:?}");
	}
}

#[test]
fn restore_puts_the_message_back_and_a_second_restore_is_refused() {
	let env = env("");
	add_account(&env, "alice");
	let id = archived(&env, "alice", 3);
	let first = run(&env, &["restore", "alice", &id.to_string()]);
	assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
	assert!(
		listed(&env, "alice").is_empty(),
		"restored entries leave the archive"
	);
	assert!(
		delivered_bodies(&env, "alice") >= 1,
		"the message is back in a mailbox"
	);
	let again = run(&env, &["restore", "alice", &id.to_string()]);
	assert_ne!(again.status.code(), Some(0));
	assert!(again.stdout.is_empty());
	let unknown = run(&env, &["restore", "alice", &Uuid::now_v7().to_string()]);
	assert_ne!(unknown.status.code(), Some(0));
	let malformed = run(&env, &["restore", "alice", "not-a-uuid"]);
	assert_eq!(malformed.status.code(), Some(2));
}
