use super::*;

fn database() -> Database {
	toml::from_str(r#"url = "postgres://epistle@localhost/epistle""#).expect("database")
}

#[test]
fn host_dump_drops_existing_objects_before_recreating_them() {
	let spec = host_pg_dump_spec(&database()).expect("dump spec");
	assert!(
		spec.argv()
			== [
				"pg_dump",
				"-Fp",
				"--clean",
				"--if-exists",
				"--no-owner",
				"--no-privileges",
				"postgres://epistle@localhost/epistle",
			],
		"host dump argv must include --clean and --if-exists to replace existing schema"
	);
}

#[test]
fn container_dump_drops_existing_objects_before_recreating_them() {
	let root = tempfile::tempdir_in(std::env::current_dir().expect("cwd")).expect("tempdir");
	let compose = root.path().join("compose.yaml");
	std::fs::write(&compose, "{}").expect("compose");
	let spec = container_pg_dump_spec(&compose).expect("dump spec");
	assert!(
		spec.argv().last().is_some_and(|script| script ==
			r#"PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec pg_dump -Fp --clean --if-exists --no-owner --no-privileges -h '/var/run/postgresql' -U 'epistle' -d 'epistle'"#),
		"container dump argv must include --clean and --if-exists to replace existing schema"
	);
}

#[test]
fn host_replay_stops_on_errors_in_one_transaction() {
	let spec = host_psql_load_spec(&database(), b"SELECT 1;\n").expect("restore spec");
	assert!(
		spec.argv()
			== [
				"psql",
				"-v",
				"ON_ERROR_STOP=1",
				"-1",
				"-X",
				"postgres://epistle@localhost/epistle"
			],
		"host replay argv must keep ON_ERROR_STOP and one transaction"
	);
	assert!(spec.stdin_payload() == Some(b"SELECT 1;\n".as_slice()));
}
