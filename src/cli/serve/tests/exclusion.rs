use super::*;

#[tokio::test]
async fn tk02_serve_refuses_migration_before_startup_writes() {
	let dir = tempfile::tempdir().unwrap();
	let _migration =
		crate::storage::lock::FileLock::acquire(&dir.path().join(".store.lock")).unwrap();
	let mut config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}",
		dir.path()
	))
	.unwrap();
	config.listeners.clear();
	let error = serve(config)
		.await
		.expect_err("serve must refuse the migration lock");
	assert!(error.to_string().contains("store is in use"), "{error}");
	assert!(!dir.path().join("log-id.key").exists());
}
