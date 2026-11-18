//! A plan that cannot be made changes nothing, and the DKIM keys of a server
//! run through the whole command.

use std::process::ExitCode;

use crate::api::ApiKeyStore;

use super::fixture::{KEYS, rotate_dir, run, server};

const NOW: u64 = 20_000 * 86_400;

#[test]
fn a_store_that_cannot_be_read_refuses_the_run_before_anything_changes() {
	let server = server();
	let path = server.data_dir.join("app_passwords.toml");
	std::fs::write(&path, b"[accounts.\"alice@example.org\"\npasswords = 3").unwrap();
	let ran = run(&server.config, NOW);
	assert_eq!(ran.code, ExitCode::FAILURE);
	assert!(ran.out.is_empty(), "{}", ran.out);
	let stored = ApiKeyStore::open(&server.data_dir)
		.unwrap()
		.hash_of(KEYS[0])
		.unwrap();
	assert_eq!(stored, server.key_hashes[0], "a key was rotated anyway");
	assert!(!rotate_dir(&server).join("journal.json").exists());
}

/// A configuration with a key of its own for `example.org`, published
/// through a `[dns]` entry, and no other secret.
fn with_dkim() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let (dir, file) = crate::cli::resource::test_config("");
	let mut paths = Vec::new();
	for name in ["default", "org"] {
		let (pem, _) = crate::dkim::generate_key().unwrap();
		let path = dir
			.path()
			.canonicalize()
			.unwrap()
			.join(format!("{name}.pem"));
		std::fs::write(&path, pem).unwrap();
		paths.push(path);
	}
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str(&format!(
		"\n[dkim]\nselector = 's1'\nkey_file = {:?}\n\n[[dkim.domain]]\nname = 'example.org'\n\
		 selector = 'own1'\nkey_file = {:?}\n\n[dns]\nprovider = 'cloudflare'\nzone = \
		 'example.org'\ntoken = '{}'\n",
		paths[0],
		paths[1],
		uuid::Uuid::new_v4().simple()
	));
	std::fs::write(file.path(), text).unwrap();
	(dir, file)
}

#[test]
fn a_domain_key_is_queued_and_one_inside_its_overlap_does_not_stop_the_run() {
	let (dir, file) = with_dkim();
	let data_dir = dir.path().canonicalize().unwrap();
	let ran = run(file.path(), NOW);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	let steps: Vec<(&str, &str, &str)> = result["steps"]
		.as_array()
		.unwrap()
		.iter()
		.map(|step| {
			(
				step["kind"].as_str().unwrap(),
				step["item"].as_str().unwrap(),
				step["result"].as_str().unwrap(),
			)
		})
		.collect();
	assert_eq!(steps, [("dkim-domain-key", "example.org", "queued")]);
	assert!(crate::dkim::domain_rotate::pending_request(&data_dir, "example.org").is_some());
	// The server served it: the key in service changed, and the selector it
	// replaced is published for a while. A run then leaves the key alone and
	// says why, instead of refusing everything else.
	let key_dir = crate::dkim::domain_rotate::state_dir(&data_dir, "example.org").unwrap();
	std::fs::remove_file(key_dir.join(crate::dkim::domain_rotate::REQUEST_FILE)).unwrap();
	let (pem, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(key_dir.join("own20000.pem"), pem).unwrap();
	let state = crate::dkim::rotate::RotationState {
		selector: "own20000".into(),
		key_file: key_dir.join("own20000.pem"),
		rotated_at: NOW,
		previous: Some(crate::dkim::rotate::Previous {
			selector: "own1".into(),
			key_file: key_dir.join("own1.pem"),
			retire_at: NOW + 7 * 86_400,
			rsa: None,
		}),
		pending: None,
		rsa: None,
	};
	std::fs::write(
		key_dir.join(crate::dkim::domain_rotate::STATE_FILE),
		serde_json::to_vec(&state).unwrap(),
	)
	.unwrap();
	let ran = run(file.path(), NOW + 86_400);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	assert!(result["steps"].as_array().unwrap().is_empty(), "{result}");
	assert!(
		result["notes"]
			.as_array()
			.unwrap()
			.iter()
			.any(|note| note.as_str().unwrap().contains("stays published until")),
		"{result}"
	);
}
