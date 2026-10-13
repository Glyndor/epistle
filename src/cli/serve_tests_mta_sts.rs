use super::*;

#[tokio::test]
async fn startup_publishes_configured_mta_sts_policy() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A real data_dir: startup creates the log pseudonym key there first. With
	// a path that cannot be created, the test passed only when an earlier test
	// in the same process had already initialised that key.
	let mut config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'",
		dir.path().join("data").display()
	))
	.expect("config");
	config.mta_sts.policy_dir = Some(dir.path().join("policy"));
	config.mta_sts.mode = crate::config::MtaStsMode::Enforce;
	config.mta_sts.max_age = 12345;
	serve(config).await.expect("startup");
	assert_eq!(
		std::fs::read_to_string(dir.path().join("policy/mta-sts.txt"))
			.expect("policy written at startup"),
		"version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 12345\n"
	);
}
