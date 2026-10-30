use super::CommandSpec;

#[test]
fn command_spec_debug_redacts_every_environment_value() {
	let spec = CommandSpec::new(vec!["pg_dump".into()])
		.with_env("PGPASSWORD", "secret-value")
		.with_env("CUSTOM", "second-value")
		.with_stdin(b"private-data".to_vec());
	let rendered = format!("{spec:?}");
	assert!(
		!rendered.contains("secret-value") && !rendered.contains("second-value"),
		"CommandSpec Debug must redact every environment value"
	);
	assert!(
		rendered
			== r#"CommandSpec { argv: ["pg_dump"], env: [("PGPASSWORD", "<redacted>"), ("CUSTOM", "<redacted>")], stdin_len: Some(12) }"#,
		"CommandSpec Debug must retain argv, redacted env keys and stdin length"
	);
}
