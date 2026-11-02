use super::*;

#[test]
fn missing_password_refuses_existing_database_volume() {
	let dir = tempfile::tempdir().unwrap();
	let mut report = Report::default();
	let result = ensure_db_password_with_probe(dir.path(), &mut report, |volume| {
		assert_eq!(
			volume, "epistle_epistle-pgdata",
			"probe must use the compose project volume name"
		);
		Ok(true)
	});
	let outcome = result
		.map(|_| "password created".to_string())
		.unwrap_or_else(|error| error.to_string());
	assert_eq!(
		outcome,
		format!(
			"database volume epistle_epistle-pgdata already exists but password file {} is missing; restore the password file from backup or remove the volume with `podman volume rm epistle_epistle-pgdata` and rerun init",
			db_password_path(dir.path()).display()
		),
		"existing database must refuse a replacement password and explain recovery"
	);
	assert!(
		!db_password_path(dir.path()).exists(),
		"refusal must leave the password absent"
	);
	assert!(
		report.steps.is_empty(),
		"refusal must not report a new password"
	);
}

#[test]
fn missing_password_refuses_unknown_volume_state() {
	let dir = tempfile::tempdir().unwrap();
	let result = ensure_db_password_with_probe(dir.path(), &mut Report::default(), |_| {
		Err(std::io::Error::other("probe unavailable"))
	});
	let outcome = result
		.map(|_| "password created".to_string())
		.unwrap_or_else(|error| error.to_string());
	assert_eq!(
		outcome, "cannot check database volume epistle_epistle-pgdata: probe unavailable",
		"unknown volume state must not mint credentials"
	);
	assert!(!db_password_path(dir.path()).exists());
}

#[test]
fn password_is_created_only_for_absent_volume_and_reused_without_probe() {
	let dir = tempfile::tempdir().unwrap();
	let path = ensure_db_password_with_probe(dir.path(), &mut Report::default(), |volume| {
		assert_eq!(volume, "epistle_epistle-pgdata");
		Ok(false)
	})
	.unwrap();
	assert_eq!(fs::metadata(&path).unwrap().len(), 32);
	let original = fs::read(&path).unwrap();
	let reused = ensure_db_password_with_probe(dir.path(), &mut Report::default(), |_| {
		panic!("existing password must not probe Podman")
	})
	.unwrap();
	assert_eq!(path, reused);
	assert!(
		fs::read(path).unwrap() == original,
		"existing password bytes must be preserved"
	);
}
