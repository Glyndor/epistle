use super::{ensure_compose_file, stack_answers};
use crate::cli::init::apply::Report;

#[test]
fn init_rerun_keeps_operator_override_bytes_and_mode() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let mut answers = stack_answers();
	answers.data_dir = dir.path().to_owned();
	answers.config_path = dir.path().join("mail.toml");
	let compose_dir = dir.path().join("compose");
	std::fs::create_dir(&compose_dir).unwrap();
	let override_path = compose_dir.join("compose.override.yaml");
	let content = b"services:\n  mail:\n    mem_limit: 1g\n";
	std::fs::write(&override_path, content).unwrap();
	std::fs::set_permissions(&override_path, std::fs::Permissions::from_mode(0o640)).unwrap();
	for webdav in [false, true] {
		answers.services.webdav = webdav;
		ensure_compose_file(&answers, true, &mut Report::default()).unwrap();
		assert!(
			std::fs::read(&override_path).unwrap() == content,
			"init must preserve the exact operator override bytes"
		);
		assert_eq!(
			std::fs::metadata(&override_path)
				.unwrap()
				.permissions()
				.mode() & 0o777,
			0o640,
			"init must preserve operator override permissions"
		);
	}
}
