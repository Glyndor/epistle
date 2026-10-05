//! Live-database tests for the `[database] password_file` plumbing: the
//! connection must read the secret from disk and present it to PostgreSQL
//! when the URL omits the password, and must refuse when the file holds the
//! wrong secret. Skipped when `DATABASE_URL` is not set, the same gating the
//! other integration tests in `tests/database.rs` and `tests/database_bans.rs`
//! apply so the `Database` workflow exercises the full matrix on every push
//! and the default `cargo test` run stays self-contained.
//!
//! The CI database is a container on the runner's loopback with no TLS,
//! which is exactly the case `DatabaseTls::Insecure` exists for. Each test
//! mints its own login role (password + role name) so reruns against a
//! persistent database stay isolated and the `wrong_password` cannot collide
//! with the right one.

use epistle::config::DatabaseTls;

/// The connection URL, or `None` when no database is configured for this run.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// Build a URL that points at the same host:port:dbname as `admin` but with
/// `user` as the user and no password. The URL the operator would put in the
/// config when `password_file` is the source of the secret.
fn url_without_password(admin: &str, user: &str) -> String {
	let parsed = url::Url::parse(admin).expect("admin URL must parse");
	let host = parsed.host_str().expect("admin URL must have a host");
	let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
	let path = parsed.path();
	format!("postgres://{user}@{host}{port}{path}")
}

/// Create a temp file the test owns, write `password` followed by a single
/// newline (the form a `podup` secret mount produces), and chmod it to the
/// `0400` mode the validator accepts. The path is returned; the `TempDir`
/// guard is leaked (the test process is short-lived and the file is the only
/// thing that matters).
fn write_password_file(path: &std::path::Path, password: &str) {
	use std::os::unix::fs::PermissionsExt as _;
	std::fs::write(path, format!("{password}\n")).expect("write password file");
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).expect("chmod 0400");
}

/// `CREATE USER` for the named role with the named password. Postgres does
/// not allow bind parameters in DDL, so the literal values are spliced in
/// with `push`. The role name and password are minted from
/// `uuid::Uuid::now_v7()` at runtime. They are untrusted-but-bounded (32
/// lowercase hex digits, no quotes, no backslashes), so splicing them in is
/// safe for the test process. This is an integration test, not a public
/// entrypoint; the same pattern appears in the existing
/// `sql_directory_loads_resolves_and_authenticates` setup at the cost of a
/// `QueryBuilder` per call.
async fn create_login_role(pool: &sqlx::PgPool, role: &str, password: &str) {
	let mut q = sqlx::QueryBuilder::new("CREATE USER \"");
	q.push(role);
	q.push("\" WITH PASSWORD '");
	q.push(password);
	q.push("' LOGIN");
	q.build().execute(pool).await.expect("create role");
}

/// Grant the permissions the new role needs to run migrations at pool
/// construction time: `USAGE` on the `public` schema to resolve objects by
/// name, `CREATE` on the schema to make the migration bookkeeping table on
/// the first connect, and full DML on the tables that already exist so the
/// sqlx migrate runner can record the migration it just applied. Without
/// these grants the pool comes up but the migration step fails with
/// SQLSTATE `42501` (`insufficient_privilege`) on either the bookkeeping
/// table or the migration's first statement; the test asserts a success
/// path so the role must reach the post-migration `SELECT 1` clean.
async fn grant_schema_access(pool: &sqlx::PgPool, role: &str) {
	let mut usage = sqlx::QueryBuilder::new("GRANT USAGE ON SCHEMA public TO \"");
	usage.push(role);
	usage.push("\"");
	usage
		.build()
		.execute(pool)
		.await
		.expect("grant usage on public");

	let mut create = sqlx::QueryBuilder::new("GRANT CREATE ON SCHEMA public TO \"");
	create.push(role);
	create.push("\"");
	create
		.build()
		.execute(pool)
		.await
		.expect("grant create on public");

	let mut dml = sqlx::QueryBuilder::new(
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"",
	);
	dml.push(role);
	dml.push("\"");
	dml.build()
		.execute(pool)
		.await
		.expect("grant dml on existing tables");

	let mut ddl = sqlx::QueryBuilder::new("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO \"");
	ddl.push(role);
	ddl.push("\"");
	ddl.build()
		.execute(pool)
		.await
		.expect("grant usage on sequences");
}

/// Drop a login role. `DROP USER` fails while the role still holds
/// privileges on the schema (the `GRANT USAGE`, `GRANT CREATE`, and
/// `GRANT SELECT, INSERT, UPDATE, DELETE` calls in
/// [`grant_schema_access`] give the role access to `public`, and a
/// successful `connect` would have given it the migration bookkeeping
/// table to own). `DROP OWNED BY` revokes the role's grants and
/// drops everything it owns in one shot; `DROP ROLE` then drops the
/// role itself. The `.expect` calls assert both steps succeeded:
/// silently swallowing the failure would leave the role behind, and
/// the next test run against a persistent database would collide
/// with the leftover `pwfile-*` role and fail with a
/// duplicate-role error. [`assert_role_absent`] then queries
/// `pg_roles` to confirm the role is actually gone: a sabotage that
/// reverts the helper to `DROP USER IF EXISTS` and discards the
/// error would still leave the row in `pg_roles`, and this
/// assertion fails the test on the next line.
async fn drop_role(pool: &sqlx::PgPool, role: &str) {
	let mut owned = sqlx::QueryBuilder::new("DROP OWNED BY \"");
	owned.push(role);
	owned.push("\"");
	owned
		.build()
		.execute(pool)
		.await
		.expect("drop owned by role");
	let mut drop = sqlx::QueryBuilder::new("DROP ROLE \"");
	drop.push(role);
	drop.push("\"");
	drop.build().execute(pool).await.expect("drop role");
	assert_role_absent(pool, role).await;
}

/// Confirm the role is no longer in `pg_roles`. The query is the
/// oracle a sabotaged `drop_role` (one that reverts to `DROP USER`
/// and discards the error) would silently fail: the `DROP USER`
/// returns an error swallowed by `let _ = ...`, the helper returns,
/// and the role remains in `pg_roles`. A future test run against a
/// persistent database would then collide with the leftover role.
/// The assertion makes that scenario fail the current test, so the
/// regression is caught at the desk, not on a later CI run.
async fn assert_role_absent(pool: &sqlx::PgPool, role: &str) {
	let row: Option<(String,)> = sqlx::query_as("SELECT rolname FROM pg_roles WHERE rolname = $1")
		.bind(role)
		.fetch_optional(pool)
		.await
		.expect("query pg_roles");
	assert!(
		row.is_none(),
		"role {role:?} was not dropped; cleanup left it behind. A sabotaged \
		 drop_role (revert to DROP USER and `let _ = ...`) would land here. \
		 Run `podman exec pg-iw psql -U postgres -d epistle_test -c \
		 \"DROP ROLE {role:?}\"` to clear the leftover by hand."
	);
}

/// `[database] password_file` holds the right password and the URL omits the
/// password: the connection succeeds and `SELECT 1` returns `1`. Pins the
/// container deployment path: podup mounts the secret at a known path, the
/// URL has no userinfo, and `connect` reads the file and presents it to
/// PostgreSQL on the same SQL surface every other integration test exercises.
#[tokio::test]
async fn connects_with_password_file_holding_the_right_secret() {
	let Some(admin) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};

	let role = format!("pwfile-{}", uuid::Uuid::now_v7().simple());
	let password = uuid::Uuid::now_v7().simple().to_string();

	// Bootstrap: connect as the admin user to create the login role with
	// the password the file will hold, and grant the schema-level
	// permissions the pool's first connect needs to run migrations.
	// `epistle::db::connect` runs migrations at pool construction, so the
	// new role must be able to CREATE tables in the target schema (the
	// public schema, for the test database) on the first connect only.
	// existing migrations on rerun require nothing the role lacks.
	let admin_pool = epistle::db::connect(&admin, DatabaseTls::Insecure, 2, None)
		.await
		.expect("admin connect");
	create_login_role(&admin_pool, &role, &password).await;
	grant_schema_access(&admin_pool, &role).await;

	let dir = tempfile::tempdir().expect("tempdir");
	let secret_path = dir.path().join("epistle_db_password");
	write_password_file(&secret_path, &password);

	let user_url = url_without_password(&admin, &role);
	let pool = epistle::db::connect(&user_url, DatabaseTls::Insecure, 2, Some(&secret_path))
		.await
		.expect("connect with password_file");

	let one: i32 = sqlx::query_scalar("SELECT 1")
		.fetch_one(&pool)
		.await
		.expect("SELECT 1");
	assert_eq!(one, 1);

	drop_role(&admin_pool, &role).await;
}

/// `[database] password_file` holds the wrong password: the connection is
/// refused with the SQLSTATE `28P01` (`invalid_password`) error code, the
/// code PostgreSQL emits for every authentication failure. The test pins the
/// direction: a bad secret must not let the pool come up under another
/// role's authentication.
#[tokio::test]
async fn fails_when_password_file_holds_the_wrong_secret() {
	let Some(admin) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};

	let role = format!("pwfile-{}", uuid::Uuid::now_v7().simple());
	let right_password = uuid::Uuid::now_v7().simple().to_string();
	let wrong_password = uuid::Uuid::now_v7().simple().to_string();

	let admin_pool = epistle::db::connect(&admin, DatabaseTls::Insecure, 2, None)
		.await
		.expect("admin connect");
	create_login_role(&admin_pool, &role, &right_password).await;

	let dir = tempfile::tempdir().expect("tempdir");
	let secret_path = dir.path().join("epistle_db_password");
	write_password_file(&secret_path, &wrong_password);

	let user_url = url_without_password(&admin, &role);
	let error = epistle::db::connect(&user_url, DatabaseTls::Insecure, 2, Some(&secret_path))
		.await
		.expect_err("connect with the wrong password must be refused");

	let DbErrorInfo { code, .. } = db_error_info(&error);
	assert_eq!(
		code, "28P01",
		"wrong password must surface as PostgreSQL SQLSTATE 28P01 (invalid_password), got {code:?}"
	);

	drop_role(&admin_pool, &role).await;
}

/// What the test cares about out of a `DbError`: the SQLSTATE code from the
/// underlying `sqlx` error, when one exists. The `Display` text is captured
/// too so a future regression can be reported alongside the code.
struct DbErrorInfo {
	code: String,
	#[allow(dead_code)]
	message: String,
}

/// Pull the SQLSTATE code and message from the `sqlx::Error` at the heart of
/// `epistle::db::DbError::Connect`. The other variants do not carry a
/// sqlx error: `ServerTooOld` and `BadServerVersion` happen after the
/// authentication completes; the test asserts `28P01` so a `Connect` error
/// is the only kind that can satisfy it.
fn db_error_info(error: &epistle::db::DbError) -> DbErrorInfo {
	use epistle::db::DbError;
	match error {
		DbError::Connect(sqlx_err) => match sqlx_err.as_database_error() {
			Some(db_err) => DbErrorInfo {
				code: db_err.code().unwrap_or_default().to_string(),
				message: db_err.message().to_string(),
			},
			None => DbErrorInfo {
				code: String::new(),
				message: sqlx_err.to_string(),
			},
		},
		other => DbErrorInfo {
			code: String::new(),
			message: other.to_string(),
		},
	}
}
