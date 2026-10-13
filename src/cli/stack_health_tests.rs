//! Tests for reading a service's health from `podup ps --format json`.

use super::service_status;

#[test]
fn the_named_service_row_is_read() {
	let json = r#"[{"Service":"db","State":"running","Health":"starting","ExitCode":0},
		{"Service":"mail","State":"running","Health":"healthy","ExitCode":0}]"#;
	assert_eq!(
		service_status(json, "mail"),
		Some(("running".to_string(), "healthy".to_string()))
	);
	assert_eq!(
		service_status(json, "db"),
		Some(("running".to_string(), "starting".to_string()))
	);
	assert_eq!(service_status(json, "clamav"), None);
	assert_eq!(service_status("not json", "mail"), None);
}
