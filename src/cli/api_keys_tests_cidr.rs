//! Tests for the `--ip-cidr` advisory `api-key create` and `api-key list`
//! carry when the container network does not hand the listener the client
//! address.

use super::*;
use std::path::Path;

/// A config whose data directory also holds a compose file giving the `mail`
/// service `network_mode`.
fn config(dir: &Path, mode: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config parses");
	let compose = crate::cli::init::compose_file_path(dir);
	std::fs::create_dir_all(compose.parent().expect("a parent")).expect("create dir");
	std::fs::write(
		&compose,
		format!("{{\"services\": {{\"mail\": {{\"network_mode\": {mode:?}}}}}}}"),
	)
	.expect("write compose");
	config
}

/// `NewKey` with the label, CIDR and the one scope every test needs.
fn key(label: &str, cidr: Option<&str>) -> NewKey {
	NewKey {
		label: label.to_string(),
		expires_at: None,
		ip_cidr: cidr.map(str::to_string),
		scopes: vec!["read".to_string()],
		domains: Vec::new(),
		account: None,
		class: None,
	}
}

#[test]
fn create_with_a_cidr_warns_when_the_network_hides_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "bridge");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		create(
			&config,
			key("ci", Some("10.0.0.0/24")),
			false,
			&mut out,
			&mut err
		),
		ExitCode::SUCCESS,
		"the advisory must not change the exit code"
	);
	let text = String::from_utf8_lossy(&err);
	assert!(text.contains("10.0.0.0/24"), "{text}");
	assert!(text.contains("network_mode \"bridge\""), "{text}");
	assert!(text.contains("pasta"), "{text}");
	// The key is still stored: the advisory is about the network, not the
	// request.
	assert_eq!(ApiKeyStore::open(dir.path()).expect("open").keys().len(), 1);
}

#[test]
fn create_with_a_cidr_is_quiet_when_pasta_keeps_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "pasta");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		create(
			&config,
			key("ci", Some("10.0.0.0/24")),
			false,
			&mut out,
			&mut err
		),
		ExitCode::SUCCESS
	);
	assert_eq!(String::from_utf8_lossy(&err), "");
}

#[test]
fn create_without_a_cidr_says_nothing_about_the_network() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "bridge");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		create(&config, key("ci", None), false, &mut out, &mut err),
		ExitCode::SUCCESS
	);
	assert_eq!(String::from_utf8_lossy(&err), "");
}

#[test]
fn create_json_carries_the_warning_without_losing_the_result() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "bridge");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		create(
			&config,
			key("ci", Some("10.0.0.0/24")),
			true,
			&mut out,
			&mut err
		),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(value["result"], "saved");
	assert_eq!(value["action"], "create");
	assert_eq!(value["label"], "ci");
	assert_eq!(value["ip_cidr"], "10.0.0.0/24");
	let warnings = value["warnings"].as_array().expect("a warnings array");
	assert_eq!(warnings.len(), 1, "{value}");
	assert!(
		warnings[0]
			.as_str()
			.unwrap_or_default()
			.contains("10.0.0.0/24"),
		"{value}"
	);
	assert!(
		String::from_utf8_lossy(&err).contains("10.0.0.0/24"),
		"the advisory must still reach a human running with --json"
	);
}

#[test]
fn create_json_leaves_the_result_object_alone_on_pasta() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "pasta");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		create(
			&config,
			key("ci", Some("10.0.0.0/24")),
			true,
			&mut out,
			&mut err
		),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert!(
		value.get("warnings").is_none(),
		"nothing to warn about must not add a key to the published result: {value}"
	);
	assert_eq!(value["ip_cidr"], "10.0.0.0/24");
}

#[test]
fn list_warns_once_for_every_key_that_carries_a_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "bridge");
	for (label, cidr) in [("ci", Some("10.0.0.0/24")), ("ops", Some("10.9.0.0/16"))] {
		let mut out = Vec::new();
		assert_eq!(
			create(&config, key(label, cidr), false, &mut out, &mut Vec::new()),
			ExitCode::SUCCESS
		);
	}
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			key("plain", None),
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(list(&config, false, &mut out, &mut err), ExitCode::SUCCESS);
	let text = String::from_utf8_lossy(&err);
	assert!(text.contains("key \"ci\""), "{text}");
	assert!(text.contains("key \"ops\""), "{text}");
	assert!(!text.contains("plain"), "{text}");
	// The listing itself is unchanged.
	let listed = String::from_utf8_lossy(&out);
	assert!(listed.contains("ip=10.0.0.0/24"), "{listed}");
}

#[test]
fn list_json_keeps_the_array_shape_and_stays_quiet() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "bridge");
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			key("ci", Some("10.0.0.0/24")),
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(list(&config, true, &mut out, &mut err), ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(
		value,
		serde_json::json!([{
			"label": "ci",
			"expires_at": null,
			"ip_cidr": "10.0.0.0/24",
			"scopes": ["read"],
			"domains": [],
			"account": null,
		}]),
		"the array shape is a published contract"
	);
}
