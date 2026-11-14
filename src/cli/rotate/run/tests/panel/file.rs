//! The key file after a run, and the installs that have none.

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;

#[test]
fn the_key_file_holds_the_new_secret_and_nothing_prints_it() {
	for json in [true, false] {
		let install = install_with_panel();
		let before = std::fs::read_to_string(key_file(&install)).unwrap();
		let hash_before = stored(&install, "panel");
		let ran = run(&install.config, NOW, json, ExitCode::SUCCESS);
		assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
		let after = std::fs::read_to_string(key_file(&install)).unwrap();
		assert!(after != before, "the key file kept the old secret");
		assert!(
			stored(&install, "panel") != hash_before,
			"the panel's key was not rotated"
		);
		assert!(
			file_is_the_stored_key(&install),
			"the key file does not hold the secret of the stored key"
		);
		// What `init` and `stack update` decide next: the file and the key
		// agree, so neither is touched.
		assert!(crate::cli::init::panel_key_is_kept(&install.data, NOW + 60));
		for stream in [&ran.out, &ran.status] {
			assert!(!stream.contains(after.trim()), "the new key was printed");
			assert!(!stream.contains(before.trim()), "the old key was printed");
		}
		if !json {
			assert!(ran.out.contains("is not printed"), "{}", ran.out);
		}
	}
}

#[test]
fn the_key_file_stays_owner_only_and_keeps_its_owner() {
	let install = install_with_panel();
	let session = key_file(&install).with_file_name("panel_session_secret");
	let owner = std::fs::metadata(&session).unwrap().uid();
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let metadata = std::fs::symlink_metadata(key_file(&install)).unwrap();
	assert!(metadata.file_type().is_file());
	assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
	assert_eq!(
		metadata.uid(),
		owner,
		"not the owner of the other panel files"
	);
}

#[test]
fn the_step_is_the_panels_and_its_secret_is_not_among_the_ones_handed_over() {
	let install = install_with_panel();
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(kinds(&ran.out), ["api-key", "panel-api-key"]);
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	let handed: Vec<&str> = result["secrets"]
		.as_array()
		.unwrap()
		.iter()
		.map(|row| row["item"].as_str().unwrap())
		.collect();
	// The other key is handed over as before, and gets no file.
	assert_eq!(handed, [OTHER]);
	assert!(!key_file(&install).with_file_name(OTHER).exists());
	// The registry row of the panel's key is done, not left to the operator.
	assert!(
		!result["remaining"]
			.as_array()
			.unwrap()
			.iter()
			.any(|row| row["id"] == "panel-api-key")
	);
}

#[test]
fn a_key_labelled_panel_without_the_file_is_an_ordinary_key_and_gets_no_file() {
	let install = install();
	let minted = crate::queue::srs::generate_secret().unwrap();
	ApiKeyStore::open(&install.data)
		.unwrap()
		.add(ApiKey {
			label: "panel".to_string(),
			hash: crate::api::api_keys::sha256_hash(&minted),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.unwrap();
	compose(&install, &["mail", "panel"]);
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert_eq!(kinds(&ran.out), ["api-key", "api-key"]);
	assert!(
		!key_file(&install).exists(),
		"a key file was made for a key that had none"
	);
	assert!(ran.actions.is_empty(), "{:?}", ran.actions);
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	let secret = result["secrets"]
		.as_array()
		.unwrap()
		.iter()
		.find(|row| row["item"] == "panel")
		.and_then(|row| row["secret"].as_str())
		.expect("the operator's own key is handed over");
	assert!(crate::api::api_keys::sha256_hash(secret) == stored(&install, "panel"));
}

#[test]
fn a_link_or_a_directory_at_the_key_file_refuses_the_run_before_anything_changes() {
	for directory in [false, true] {
		let install = install_with_panel();
		let path = key_file(&install);
		let elsewhere = path.with_file_name("elsewhere");
		std::fs::rename(&path, &elsewhere).unwrap();
		if directory {
			std::fs::create_dir(&path).unwrap();
		} else {
			std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
		}
		let before = (stored(&install, OTHER), stored(&install, "panel"));
		let kept = std::fs::read(&elsewhere).unwrap();
		let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
		assert_eq!(ran.code, ExitCode::FAILURE);
		assert!(ran.out.is_empty(), "{}", ran.out);
		assert_eq!(
			(stored(&install, OTHER), stored(&install, "panel")),
			before,
			"a key was rotated anyway"
		);
		assert_eq!(std::fs::read(&elsewhere).unwrap(), kept);
		assert!(!install.data.join("rotate/journal.json").exists());
	}
}
