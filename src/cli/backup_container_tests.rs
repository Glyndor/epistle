//! Tests for the container-side command spec: the `podup -f <compose>
//! exec -T db` argv shape, the absence of a password in argv (the
//! container shell reads the mounted secret into `PGPASSWORD`),
//! and the `podup cp` + `podup exec psql` two-step used by the
//! restore path.

use super::*;
use crate::cli::init::compose_file_path;
use crate::config::Database;
use std::path::PathBuf;

fn write_minimal_compose(data_dir: &std::path::Path) -> PathBuf {
	let path = compose_file_path(data_dir);
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent).expect("mkdir compose");
	}
	std::fs::write(&path, b"{\"name\":\"stub\"}\n").expect("write compose");
	path
}

fn dump_shell() -> &'static str {
	r#"PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec pg_dump -Fp --no-owner --no-privileges -h '/var/run/postgresql' -U 'epistle' -d 'epistle'"#
}

fn restore_shell() -> &'static str {
	r#"PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec psql -v ON_ERROR_STOP=1 -1 -X -f '/tmp/epistle-restore.sql' -h '/var/run/postgresql' -U 'epistle' -d 'epistle'"#
}

fn assert_password_stays_in_container(spec: &CommandSpec) {
	assert!(
		spec.argv().last().is_some_and(|arg| {
			arg.starts_with(r#"PGPASSWORD="$(cat '/run/secrets/epistle_db_password')" exec "#)
		}),
		"container password must be read by sh inside db"
	);
	assert!(
		!spec.argv().iter().any(|arg| arg.contains("password=")),
		"container argv must not contain a password value"
	);
}

#[test]
fn container_pg_dump_argv_targets_db_service_with_no_tty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let spec = container_pg_dump_spec(&compose).expect("spec");
	let argv = spec.argv();
	assert_eq!(argv[0], "podup", "argv[0] must be podup: {argv:?}");
	assert_eq!(argv[1], "-f", "argv[1] must be -f: {argv:?}");
	assert_eq!(argv[2], compose.to_string_lossy().to_string());
	assert_eq!(argv[3], "exec", "argv[3] must be exec: {argv:?}");
	assert_eq!(argv[4], "-T", "argv[4] must be -T: {argv:?}");
	assert_eq!(argv[5], "db", "argv[5] must be db: {argv:?}");
	assert!(
		argv[6..] == ["sh", "-c", dump_shell()],
		"container dump must read the mounted secret into PGPASSWORD before exec pg_dump"
	);
}

#[test]
fn container_pg_dump_argv_never_carries_a_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let spec = container_pg_dump_spec(&compose).expect("spec");
	assert_password_stays_in_container(&spec);
	assert!(
		spec.env().is_empty(),
		"container dump must load its password inside db, without host environment additions"
	);
}

#[test]
fn container_pg_dump_argv_targets_the_unix_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let spec = container_pg_dump_spec(&compose).expect("spec");
	assert!(
		spec.argv().last().is_some_and(|arg| arg == dump_shell()),
		"container dump must use the quoted Unix socket, compose user and compose database"
	);
}

#[test]
fn container_pg_dump_missing_compose_surfaces_compose_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("does/not/exist/compose.yaml");
	let result = container_pg_dump_spec(&compose);
	let err = result.expect_err("must error on a missing compose file");
	let display = format!("{err}");
	assert!(
		display.contains(&compose.display().to_string()),
		"error must name the missing path: {display}"
	);
}

#[test]
fn container_psql_load_argv_targets_db_service_with_no_tty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let spec = container_psql_load_spec(&compose, b"select 1;\n").expect("spec");
	let argv = spec.argv();
	assert_eq!(argv[0], "podup");
	assert_eq!(argv[3], "exec");
	assert_eq!(argv[4], "-T");
	assert_eq!(argv[5], "db");
	assert!(
		argv[6..] == ["sh", "-c", restore_shell()],
		"container restore must load the mounted secret and run psql with ON_ERROR_STOP and one transaction"
	);
	assert!(
		spec.stdin_payload().is_none(),
		"container restore must use the copied SQL file"
	);
}

#[test]
fn container_psql_load_argv_never_carries_a_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let spec = container_psql_load_spec(&compose, b"select 1;\n").expect("spec");
	assert_password_stays_in_container(&spec);
	assert!(
		spec.env().is_empty(),
		"container restore must load its password inside db, without host environment additions"
	);
}

#[test]
fn pg_dump_spec_picks_container_branch_when_compose_is_present() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_minimal_compose(dir.path());
	let body = r#"url = "postgres://epistle@%2Frun%2Fpostgresql/epistle""#.to_string();
	let db: Database = toml::from_str(&body).expect("db");
	let spec = pg_dump_spec(&db, dir.path()).expect("spec");
	assert_eq!(
		spec.argv()[0],
		"podup",
		"compose present means the container path runs podup: {:?}",
		spec.argv()
	);
}

#[test]
fn pg_dump_spec_picks_host_branch_when_compose_is_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let body = r#"url = "postgres://epistle@%2Frun%2Fpostgresql/epistle""#.to_string();
	let db: Database = toml::from_str(&body).expect("db");
	let spec = pg_dump_spec(&db, dir.path()).expect("spec");
	assert_eq!(
		spec.argv()[0],
		"pg_dump",
		"compose absent means the host path runs pg_dump directly: {:?}",
		spec.argv()
	);
}

#[test]
fn container_cp_into_spec_targets_the_db_service() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let host = dir.path().join("host.sql");
	std::fs::write(&host, b"select 1;\n").expect("write host");
	let spec = container_cp_into_spec(&compose, &host, "/tmp/epistle-restore.sql").expect("spec");
	let argv = spec.argv();
	assert_eq!(argv[0], "podup");
	assert_eq!(argv[3], "cp");
	assert!(
		argv.contains(&"db:/tmp/epistle-restore.sql".to_string()),
		"the destination must be `db:<container path>`: {argv:?}"
	);
}

#[test]
fn container_load_spec_picks_container_path_when_compose_exists() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_minimal_compose(dir.path());
	let body = r#"url = "postgres://epistle@%2Frun%2Fpostgresql/epistle""#.to_string();
	let db: Database = toml::from_str(&body).expect("db");
	let spec = psql_load_spec(&db, dir.path(), b"select 1;\n").expect("spec");
	assert_eq!(
		spec.argv()[0],
		"podup",
		"compose present means the restore runs through podup cp + exec: {:?}",
		spec.argv()
	);
	assert!(
		spec.argv().contains(&"exec".to_string()),
		"the exec half of the two-step runs psql inside the db service: {:?}",
		spec.argv()
	);
}

#[test]
fn container_commands_ignore_host_password_and_untrusted_connection_values() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = write_minimal_compose(dir.path());
	let db: Database = toml::from_str(
		r#"url = "postgres://untrusted:host-secret-sentinel@invalid/untrusted?password=query-secret-sentinel"
password_file = "/nonexistent/$(untrusted-secret-file)""#,
	)
	.expect("db");
	for (spec, expected) in [
		(pg_dump_spec(&db, dir.path()).expect("dump"), dump_shell()),
		(
			psql_load_spec(&db, dir.path(), b"select 1;\n").expect("restore"),
			restore_shell(),
		),
	] {
		let expected_argv = [
			"podup",
			"-f",
			compose.to_str().expect("compose path"),
			"exec",
			"-T",
			"db",
			"sh",
			"-c",
			expected,
		];
		assert!(
			spec.argv() == expected_argv,
			"container argv must use only fixed compose connection literals"
		);
		assert!(
			!spec.argv().iter().any(|arg| {
				arg.contains("host-secret-sentinel") || arg.contains("query-secret-sentinel")
			}),
			"host URL passwords must not appear in container argv"
		);
		assert_password_stays_in_container(&spec);
	}
}
