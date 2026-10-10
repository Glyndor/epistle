use super::build_command;
use std::ffi::OsString;

#[test]
fn every_stack_command_uses_override_only_when_present() {
	let dir = tempfile::tempdir().unwrap();
	let compose = dir.path().join("compose.yaml");
	std::fs::write(&compose, "{}").unwrap();
	let override_path = dir.path().join("compose.override.yaml");
	for exists in [false, true] {
		if exists {
			std::fs::write(&override_path, "services: {}").unwrap();
		}
		for extra in [
			vec!["up", "-d"],
			vec!["down"],
			vec!["ps", "--format", "json"],
			vec!["logs", "--follow", "mail"],
			vec!["restart", "mail"],
			vec!["autostart", "install"],
			vec!["autostart", "uninstall"],
		] {
			let command = build_command("podup", &compose, &extra);
			let actual: Vec<_> = command.get_args().map(OsString::from).collect();
			let mut expected = vec![OsString::from("-f"), compose.as_os_str().to_owned()];
			if exists {
				expected.extend([OsString::from("-f"), override_path.as_os_str().to_owned()]);
			}
			expected.extend(extra.iter().map(OsString::from));
			assert_eq!(
				actual, expected,
				"every stack invocation must include the existing operator override"
			);
		}
	}
}
