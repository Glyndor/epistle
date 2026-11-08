//! Tests for the permission rule the configuration file must satisfy.

use super::*;

#[cfg(unix)]
#[test]
fn rejects_group_or_world_accessible_config() {
	use std::os::unix::fs::PermissionsExt;
	let file = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).expect("chmod");
	assert!(matches!(
		Config::load(file.path()),
		Err(ConfigError::InsecurePermissions { .. })
	));
}
