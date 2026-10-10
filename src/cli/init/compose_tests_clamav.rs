use super::*;
use serde_json::json;

#[test]
fn mandatory_clamav_stack_and_socket_config() {
	let answers = minimal_answers();
	let value = render(&answers, false);
	let clamd = &value["services"]["clamav"];
	assert_eq!(
		clamd["image"], "docker.io/clamav/clamav:1.4",
		"mandatory clamd image is missing"
	);
	assert_eq!(clamd["network_mode"], "none");
	assert_eq!(clamd["environment"]["CLAMAV_NO_FRESHCLAMD"], "true");
	assert_eq!(clamd["healthcheck"]["start_period"], "10m");
	assert_eq!(
		clamd["healthcheck"]["test"],
		json!([
			"CMD",
			"clamdscan",
			"--config-file=/etc/clamav/epistle-clamd.conf",
			"--ping=1"
		])
	);
	assert!(
		clamd["volumes"]
			.as_array()
			.unwrap()
			.contains(&json!("clamd-socket:/run/clamav"))
	);
	let fresh = &value["services"]["freshclam"];
	assert_eq!(fresh["image"], "docker.io/clamav/clamav:1.4");
	assert_eq!(fresh["network_mode"], "pasta");
	assert_eq!(fresh["environment"]["CLAMAV_NO_CLAMD"], "true");
	assert!(fresh.get("ports").is_none());
	for service in [clamd, fresh] {
		assert!(
			service["volumes"]
				.as_array()
				.unwrap()
				.contains(&json!("clamav-db:/var/lib/clamav"))
		);
	}
	assert_eq!(
		value["services"]["mail"]["depends_on"]["clamav"]["condition"],
		"service_healthy"
	);
	assert!(
		value["services"]["mail"]["volumes"]
			.as_array()
			.unwrap()
			.contains(&json!("clamd-socket:/run/clamav"))
	);
	assert!(value["volumes"].get("clamd-socket").is_some());
	assert!(value["volumes"].get("clamav-db").is_some());
}

#[test]
fn clamd_config_controls_shared_socket_permissions() {
	let dir = tempfile::tempdir().unwrap();
	let mut answers = minimal_answers();
	answers.data_dir = dir.path().join("data");
	answers.config_path = dir.path().join("config/mail.toml");
	ensure_compose_file(&answers, false, &mut Report::default()).unwrap();
	let text = fs::read_to_string(answers.data_dir.join("compose/clamd.conf")).unwrap_or_default();
	let fields: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once(' ')).collect();
	assert_eq!(
		fields.get("LocalSocketMode"),
		Some(&"666"),
		"shared clamd socket must allow mail uid 65532"
	);
	assert_eq!(fields.get("LocalSocket"), Some(&"/run/clamav/clamd.sock"));
	assert_eq!(fields.get("DatabaseDirectory"), Some(&"/var/lib/clamav"));
	assert_eq!(fields.get("User"), Some(&"clamav"));
	assert!(!fields.contains_key("TCPSocket"));
}
