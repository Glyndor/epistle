use super::*;

#[test]
fn generated_config_enables_clamd_socket() {
	let answers = crate::cli::init::compose::minimal_answers();
	let desired = build_config(
		&answers,
		"::".parse().unwrap(),
		Some(Path::new("/key")),
		None,
		Path::new("/cert"),
		Path::new("/tls-key"),
	)
	.unwrap();
	let config: toml::Value = toml::from_str(&toml::to_string(&desired).unwrap()).unwrap();
	assert_eq!(
		config
			.get("antispam")
			.and_then(|a| a.get("clamd_socket"))
			.and_then(toml::Value::as_str),
		Some("/run/clamav/clamd.sock"),
		"generated config must enable the stack scanner"
	);
}
