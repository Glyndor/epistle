//! `epistle status` says which key protects each tenant and what still
//! needs the operator.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::cli::status::report::Level;
use crate::cli::status::storage_keys_area::evaluate;
use crate::config::Config;
use crate::storage::rekey::{Direction, Journal, journal};

fn key(dir: &Path, name: &str) -> (PathBuf, String) {
	let path = dir.join(name);
	let key = crate::storage::generate_key_base64().expect("csprng");
	std::fs::write(&path, &key).expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	(path, key)
}

fn config(dir: &Path, tenant_keys: bool, retired: Option<&Path>) -> (Config, Vec<String>) {
	let (server, server_key) = key(dir, "server.key");
	let (acme, acme_key) = key(dir, "acme.key");
	let retired_line = retired
		.map(|path| format!("retired_key_files = [{:?}]\n", path.display().to_string()))
		.unwrap_or_default();
	let text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [\"acme.test\", \"globex.test\"]\n\n\
		 [storage]\nencrypt_at_rest = true\ntenant_keys = {tenant_keys}\nencryption_key_file = {server:?}\n{retired_line}\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"acme.test\"]\nencryption_key_file = {acme:?}\n\n\
		 [[tenant]]\nname = \"globex\"\ndomains = [\"globex.test\"]\n",
		data = dir.display().to_string(),
		server = server.display().to_string(),
		acme = acme.display().to_string(),
	);
	let path = dir.join("mail.toml");
	std::fs::write(&path, text).expect("config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	(
		Config::load(&path).expect("load"),
		vec![server_key, acme_key],
	)
}

fn detail(report: &crate::cli::status::report::AreaReport, name: &str) -> String {
	report
		.items
		.iter()
		.find(|item| item.name == name)
		.map(|item| item.detail.clone())
		.unwrap_or_default()
}

#[test]
fn each_tenant_shows_its_key_and_no_key_material_is_printed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (config, keys) = config(dir.path(), true, None);
	let report = evaluate(&config);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(
		detail(&report, "tenant acme").starts_with("own key "),
		"{report:?}"
	);
	assert!(
		detail(&report, "tenant globex").contains("the server key"),
		"{report:?}"
	);
	assert_ne!(detail(&report, "server"), detail(&report, "tenant acme"));
	let printed = format!("{report:?}");
	assert!(keys.iter().all(|key| !printed.contains(key.as_str())));
}

#[test]
fn tenant_keys_off_retired_keys_and_an_unfinished_run_are_warnings() {
	let dir = tempfile::tempdir().expect("tempdir");
	let retired = dir.path().join("old.key");
	std::fs::write(
		&retired,
		crate::storage::generate_key_base64().expect("csprng"),
	)
	.expect("old");
	std::fs::set_permissions(&retired, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let (config, _) = config(dir.path(), false, Some(&retired));
	journal::write(&config.data_dir, &Journal::new(Direction::Forward)).expect("journal");
	let report = evaluate(&config);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert!(detail(&report, "tenant writes").contains("tenant_keys is off"));
	assert!(detail(&report, "retired server key #1").contains("remove it once"));
	assert!(detail(&report, "re-encryption").contains("unfinished"));
}

#[test]
fn a_key_file_that_does_not_load_fails_the_area() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (config, _) = config(dir.path(), true, None);
	std::fs::set_permissions(
		dir.path().join("acme.key"),
		std::fs::Permissions::from_mode(0o644),
	)
	.expect("chmod");
	let report = evaluate(&config);
	assert_eq!(report.status, Level::Fail, "{report:?}");
}
