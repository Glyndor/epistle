//! A domain's own DKIM keys are in the backup, and the warning names the ones
//! that are not.

use std::os::unix::fs::PermissionsExt;

use super::helpers::*;
use super::*;

fn config(data_dir: &std::path::Path, outside: &std::path::Path) -> Config {
	let inside = data_dir.join("keys/dkim/inside.example/ed25519.pem");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {data_dir:?}\n\
		 domains = ['inside.example', 'outside.example']\n\
		 [dkim]\nselector = 's1'\nkey_file = {data:?}\n\
		 [[dkim.domain]]\nname = 'inside.example'\nselector = 'own1'\nkey_file = {inside:?}\n\
		 [[dkim.domain]]\nname = 'outside.example'\nselector = 'own1'\nkey_file = {outside:?}\n",
		data = data_dir.join("keys/s1.pem"),
	))
	.expect("config")
}

#[test]
fn the_archive_carries_the_keys_under_data_dir_and_the_warning_names_the_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let key = data_dir.join("keys/dkim/inside.example/ed25519.pem");
	std::fs::create_dir_all(key.parent().unwrap()).expect("dirs");
	std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nfake\n-----END\n").expect("write");
	std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let outside = dir.path().join("elsewhere/outside.pem");

	let mut out = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(
		run(&config(&data_dir, &outside), &mut out, &mut warnings),
		ExitCode::SUCCESS
	);
	let entries = read_tar_entries(&gunzip(&out));
	let archived = entries
		.iter()
		.find(|(name, _, _)| name.ends_with("keys/dkim/inside.example/ed25519.pem"))
		.expect("the domain's key is in the archive");
	assert_eq!(archived.1, 0o600, "and keeps its mode");

	let text = String::from_utf8(warnings).expect("utf-8");
	assert!(
		text.contains(&format!(
			"[[dkim.domain]] outside.example key file = {}",
			outside.display()
		)),
		"{text}"
	);
	assert!(
		!text.contains("inside.example key file"),
		"a key the archive carries is not listed as missing: {text}"
	);
}
