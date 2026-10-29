use super::*;

fn config_in(dir: &std::path::Path) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[dkim]\nselector = 'original'\nkey_file = {:?}\n",
		dir,
		dir.join("original.key")
	))
	.expect("config")
}

#[test]
fn invalid_rotation_state_is_reported() {
	let dir = tempfile::tempdir().expect("directory");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("original.key"), pem).expect("key file");
	std::fs::write(dir.path().join("dkim-rotation.json"), "invalid JSON").expect("state");
	let mut out = Vec::new();
	assert_eq!(
		run(&config_in(dir.path()), false, &mut out),
		ExitCode::FAILURE,
		"dns-records must fail for invalid rotation state"
	);
	assert!(
		!String::from_utf8_lossy(&out).contains("original._domainkey"),
		"dns-records must not fall back to the configured selector"
	);
}

#[test]
fn relative_state_key_path_resolves_against_data_dir() {
	let dir = tempfile::tempdir().expect("directory");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("rotated.key"), pem).expect("key file");
	std::fs::write(
		dir.path().join("dkim-rotation.json"),
		r#"{"selector":"ed99","key_file":"rotated.key","rotated_at":1,"previous":null}"#,
	)
	.expect("state");
	let mut out = Vec::new();
	assert_eq!(
		run(&config_in(dir.path()), false, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8_lossy(&out);
	assert!(
		text.contains("ed99._domainkey.example.org"),
		"expected the rotated selector from a relative key path, got: {text}"
	);
}
