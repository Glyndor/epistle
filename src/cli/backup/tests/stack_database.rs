//! With a compose stack present, a `[database] url` that is not the stack's
//! own database is refused by both halves, instead of the stack's database
//! being dumped and overwritten in its place.

use super::*;
use crate::cli::init::compose_file_path;
use crate::config::Database;

fn stack_with_url(url: &str) -> (tempfile::TempDir, Database) {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = compose_file_path(dir.path());
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("mkdir");
	std::fs::write(&compose, b"{\"name\":\"stub\"}\n").expect("write compose");
	let db: Database = toml::from_str(&format!("url = \"{url}\"")).expect("db");
	(dir, db)
}

#[test]
fn external_database_url_with_a_compose_stack_is_refused_by_the_dump() {
	let (dir, db) = stack_with_url("postgres://epistle:pw@db.example.net/mail");
	let error = pg_dump_spec(&db, dir.path()).expect_err("must not dump the stack's database");
	assert!(matches!(error, BackupError::DatabaseNotInStack), "{error}");
}

#[test]
fn external_database_url_with_a_compose_stack_is_refused_by_the_restore() {
	let (dir, db) = stack_with_url("postgres://epistle:pw@db.example.net/mail");
	let spawned = std::cell::Cell::new(false);
	let resolver = |_: &str| {
		spawned.set(true);
		None
	};
	let error = db_dump_load(&db, dir.path(), &resolver)
		.expect_err("must not write into the stack's database");
	assert!(matches!(error, BackupError::DatabaseNotInStack), "{error}");
	assert!(!spawned.get(), "nothing may run before the refusal");
	let error = psql_load_spec(&db, dir.path(), b"select 1;\n", "/tmp/x.sql")
		.expect_err("the load spec must refuse too");
	assert!(matches!(error, BackupError::DatabaseNotInStack), "{error}");
}

#[test]
fn the_stack_url_is_accepted_whatever_the_password_or_options() {
	for url in [
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		"postgresql://epistle:pw@%2Frun%2Fpostgresql/epistle?sslmode=disable",
	] {
		let (dir, db) = stack_with_url(url);
		assert!(pg_dump_spec(&db, dir.path()).is_ok(), "{url}");
	}
}

#[test]
fn another_database_or_role_on_the_stack_socket_is_refused() {
	for url in [
		"postgres://epistle@%2Frun%2Fpostgresql/other",
		"postgres://other@%2Frun%2Fpostgresql/epistle",
		"postgres://epistle@%2Ftmp/epistle",
	] {
		let (dir, db) = stack_with_url(url);
		assert!(pg_dump_spec(&db, dir.path()).is_err(), "{url}");
	}
}

fn db_dump_load(
	db: &Database,
	data_dir: &std::path::Path,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	crate::cli::backup::db_dump::load_dump_with(db, data_dir, b"select 1;\n", resolver)
}
