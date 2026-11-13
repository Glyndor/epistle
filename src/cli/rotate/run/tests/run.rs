//! A whole run, a second run after it, and the runs that must not start.

use std::process::ExitCode;

use crate::api::ApiKeyStore;

use super::checks::rotated_once;
use super::fixture::{KEYS, rotate_dir, run, server};

const NOW: u64 = 1_900_000_000;

#[test]
fn a_run_rotates_every_secret_once_and_hands_the_new_ones_over() {
	let server = server();
	let ran = run(&server.config, NOW);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let result = rotated_once(&server, &ran.out);
	assert_eq!(result["resumed"], false);
	let kinds: Vec<&str> = result["steps"]
		.as_array()
		.unwrap()
		.iter()
		.map(|step| step["kind"].as_str().unwrap())
		.collect();
	assert_eq!(
		kinds,
		[
			"api-key",
			"api-key",
			"app-password",
			"webhook-secret",
			"srs-secret",
			"restart"
		]
	);
	// No stack here, so the operator is told to restart.
	assert_eq!(result["reload"], "restart-needed");
	assert!(ran.status.contains("The server must be restarted."));
	assert_eq!(ran.restarts, 0);
	// The SRS secret never leaves the server.
	assert!(
		!result["secrets"]
			.as_array()
			.unwrap()
			.iter()
			.any(|row| row["kind"] == "srs-secret")
	);
	// The rows this run does not carry out are left for the operator.
	let left: Vec<&str> = result["remaining"]
		.as_array()
		.unwrap()
		.iter()
		.map(|row| row["id"].as_str().unwrap())
		.collect();
	for id in [
		"storage-encryption-key",
		"database-password",
		"oauth-signing-key",
	] {
		assert!(left.contains(&id), "{id} is not listed as left to do");
	}
	assert!(!left.contains(&"api-key"));
	// What follows a row it carried out, and nothing for a key it had none of.
	let then: Vec<&str> = result["then"]
		.as_array()
		.unwrap()
		.iter()
		.map(|line| line.as_str().unwrap())
		.collect();
	assert!(then.iter().any(|line| line.starts_with("api-key: ")));
	assert!(
		!then
			.iter()
			.any(|line| line.starts_with("dkim-signing-key: "))
	);
}

#[test]
fn a_run_after_a_finished_one_is_a_new_run_and_rotates_again() {
	let server = server();
	assert_eq!(run(&server.config, NOW).code, ExitCode::SUCCESS);
	let first = ApiKeyStore::open(&server.data_dir)
		.unwrap()
		.hash_of(KEYS[0])
		.unwrap();
	let ran = run(&server.config, NOW + 86_400);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	assert_eq!(result["resumed"], false);
	let second = ApiKeyStore::open(&server.data_dir)
		.unwrap()
		.hash_of(KEYS[0])
		.unwrap();
	assert_ne!(first, second, "the second run did not rotate");
}

#[test]
fn a_journal_that_cannot_be_read_stops_the_run_before_anything_changes() {
	let server = server();
	let dir = rotate_dir(&server);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("journal.json"), b"{ not json").unwrap();
	let ran = run(&server.config, NOW);
	assert_eq!(ran.code, ExitCode::FAILURE);
	let stored = ApiKeyStore::open(&server.data_dir)
		.unwrap()
		.hash_of(KEYS[0])
		.unwrap();
	assert_eq!(stored, server.key_hashes[0], "a key was rotated anyway");
	assert_eq!(
		std::fs::read(dir.join("journal.json")).unwrap(),
		b"{ not json",
		"the journal was replaced"
	);
}

#[test]
fn a_run_while_another_holds_the_lock_is_refused() {
	let server = server();
	let dir = rotate_dir(&server);
	std::fs::create_dir_all(&dir).unwrap();
	let _held = crate::storage::lock::FileLock::try_acquire(&dir.join("lock"))
		.unwrap()
		.unwrap();
	let ran = run(&server.config, NOW);
	assert_eq!(ran.code, ExitCode::FAILURE);
	let stored = ApiKeyStore::open(&server.data_dir)
		.unwrap()
		.hash_of(KEYS[0])
		.unwrap();
	assert_eq!(stored, server.key_hashes[0], "a key was rotated anyway");
	assert!(!dir.join("journal.json").exists());
}
