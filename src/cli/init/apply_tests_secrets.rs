//! `init` keeps the storage and OAuth signing keys outside data_dir, and
//! moves them there on an install that had them under `data_dir/keys`.

use std::path::PathBuf;

use super::*;

fn answers(root: &std::path::Path) -> Answers {
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.data_dir = root.join("data");
	answers.config_path = root.join("etc/mail.toml");
	answers.image = Some("localhost/epistle:dev".to_string());
	answers
}

fn config(answers: &Answers) -> toml::Value {
	toml::from_str(&std::fs::read_to_string(&answers.config_path).unwrap()).unwrap()
}

#[test]
fn a_fresh_install_writes_both_keys_outside_data_dir() {
	let root = tempfile::tempdir().unwrap();
	let answers = answers(root.path());
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	let secrets = root.path().join("secrets");
	assert!(secrets.join("storage.key").is_file());
	assert!(secrets.join("oauth_signing.key").is_file());
	assert!(!answers.data_dir.join("keys/storage.key").exists());
	assert!(!answers.data_dir.join("keys/oauth_signing.key").exists());
	assert!(answers.data_dir.join("keys/oauth_public.key").is_file());
	assert_eq!(
		config(&answers)["storage"]["encryption_key_file"].as_str(),
		Some(secrets.join("storage.key").to_str().unwrap())
	);
}

#[test]
fn an_older_install_has_its_keys_moved_and_its_config_repointed() {
	let root = tempfile::tempdir().unwrap();
	let answers = answers(root.path());
	assert!(apply(&answers).error.is_none());
	// Put the tree back the way init left it before the keys moved.
	let secrets = root.path().join("secrets");
	let keys = answers.data_dir.join("keys");
	let storage = std::fs::read(secrets.join("storage.key")).unwrap();
	let oauth = std::fs::read(secrets.join("oauth_signing.key")).unwrap();
	std::fs::remove_dir_all(&secrets).unwrap();
	std::fs::write(keys.join("storage.key"), &storage).unwrap();
	std::fs::write(keys.join("oauth_signing.key"), &oauth).unwrap();
	let old = keys.join("storage.key");
	let text = std::fs::read_to_string(&answers.config_path).unwrap();
	let text = text.replace(
		secrets.join("storage.key").to_str().unwrap(),
		old.to_str().unwrap(),
	);
	crate::storage::write_secret(&answers.config_path, text.as_bytes()).unwrap();

	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	assert_eq!(std::fs::read(secrets.join("storage.key")).unwrap(), storage);
	assert_eq!(
		std::fs::read(secrets.join("oauth_signing.key")).unwrap(),
		oauth
	);
	assert!(!old.exists());
	assert_eq!(
		config(&answers)["storage"]["encryption_key_file"].as_str(),
		Some(secrets.join("storage.key").to_str().unwrap())
	);
	let moved: Vec<&PathBuf> = outcome
		.report
		.steps
		.iter()
		.filter_map(|step| match step {
			ReportStep::Moved { to, .. } => Some(to),
			_ => None,
		})
		.collect();
	assert_eq!(moved.len(), 2, "{:?}", outcome.report);
}

#[test]
fn stack_update_moves_the_keys_creates_missing_ones_and_repoints_the_config() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	let keys = data_dir.join("keys");
	std::fs::create_dir_all(&keys).unwrap();
	std::fs::write(keys.join("storage.key"), b"old-storage").unwrap();
	let config = root.path().join("mail.toml");
	let text = format!(
		"# kept\n[storage]\nencrypt_at_rest = true\nencryption_key_file = \"{}\"\n",
		keys.join("storage.key").display()
	);
	std::fs::write(&config, &text).unwrap();
	let lines = super::prepare_keys_for_update(&data_dir, &config, true).unwrap();
	let secrets = root.path().join("secrets");
	assert_eq!(
		std::fs::read(secrets.join("storage.key")).unwrap(),
		b"old-storage"
	);
	assert!(
		secrets.join("oauth_signing.key").is_file(),
		"created as init would"
	);
	assert!(keys.join("oauth_public.key").is_file());
	let after = std::fs::read_to_string(&config).unwrap();
	assert!(after.starts_with("# kept\n"), "{after}");
	assert!(
		after.contains(secrets.join("storage.key").to_str().unwrap()),
		"{after}"
	);
	assert!(secrets.join("epistle_db_admin_password").is_file());
	assert_eq!(lines.len(), 5, "{lines:?}");
	assert_eq!(
		super::prepare_keys_for_update(&data_dir, &config, true).unwrap(),
		Vec::<String>::new(),
		"a second update changes nothing"
	);
}

#[test]
fn the_admin_password_is_minted_once_and_kept() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	let mut report = Report::default();
	let path = crate::cli::init::compose::ensure_db_admin_password(&data_dir, &mut report).unwrap();
	assert_eq!(path, root.path().join("secrets/epistle_db_admin_password"));
	let first = std::fs::read(&path).unwrap();
	assert_eq!(first.len(), 32);
	crate::cli::init::compose::ensure_db_admin_password(&data_dir, &mut report).unwrap();
	assert_eq!(std::fs::read(&path).unwrap(), first);
	assert!(matches!(report.steps.last(), Some(ReportStep::Reused(_))));
}

#[test]
fn the_plan_names_the_admin_password_beside_data_dir() {
	let root = tempfile::tempdir().unwrap();
	let mut answers = answers(root.path());
	answers.services.database = true;
	let mut rendered = String::new();
	plan(&answers)
		.expect("plan")
		.write_to(&mut rendered)
		.unwrap();
	let admin = root.path().join("secrets/epistle_db_admin_password");
	assert!(
		rendered.contains(&format!(
			"database admin password: generate {}",
			admin.display()
		)),
		"{rendered}"
	);
}
