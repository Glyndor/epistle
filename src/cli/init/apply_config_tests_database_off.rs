use super::*;

fn desired(database: bool) -> toml::Value {
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.services.database = database;
	let config = build_config(
		&answers,
		"::".parse().unwrap(),
		Some(Path::new("/key")),
		None,
		Path::new("/cert"),
		Path::new("/tls-key"),
	)
	.unwrap();
	toml::from_str(&toml::to_string(&config).unwrap()).unwrap()
}

#[test]
fn disabling_stack_database_removes_generated_socket_section() {
	let existing = desired(true);
	let merged = reconcile(existing, desired(false), false);
	assert!(
		merged.get("database").is_none(),
		"disabling the stack database must remove its generated socket section"
	);
}

#[test]
fn disabling_stack_database_preserves_operator_database_section() {
	let mut existing = desired(false);
	let operator: toml::Value = toml::from_str("[database]\nurl = 'postgres://epistle@db.example.org/epistle?sslmode=verify-full'\npassword_file = '/secure/postgres-password'\nmax_connections = 17\n").unwrap();
	existing
		.as_table_mut()
		.unwrap()
		.insert("database".into(), operator["database"].clone());
	let merged = reconcile(existing, desired(false), false);
	assert_eq!(
		merged["database"], operator["database"],
		"operator database settings must survive database-off reruns"
	);
}
