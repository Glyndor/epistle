//! The PostgreSQL roles of the stack.
//!
//! The image makes `POSTGRES_USER` the bootstrap superuser, and PostgreSQL
//! 16 and later refuse to take SUPERUSER away from it ("The bootstrap
//! superuser must have the SUPERUSER attribute", measured on postgres:18).
//! So the bootstrap role is `epistle_admin`, with its own password mounted
//! only into `db`, and `epistle`, the role mail connects as, is created by
//! [`INIT_SCRIPT`] with no attribute beyond LOGIN and owns the `epistle`
//! database. The migrations only create tables and indexes in `public`,
//! which the database owner may do.
//!
//! Stacks initialised before this have `epistle` as the bootstrap
//! superuser. [`HARDEN_SCRIPT`] renames it to `epistle_admin` and creates a
//! new `epistle` that takes over the database and everything in `public`.

/// The bootstrap superuser.
pub(crate) const ADMIN_USER: &str = "epistle_admin";

/// The compose secret holding the admin password, and its path in `db`.
pub(crate) const ADMIN_SECRET: &str = "epistle_db_admin_password";

/// Where the image mounts [`ADMIN_SECRET`].
pub(crate) const ADMIN_PASSWORD_FILE: &str = "/run/secrets/epistle_db_admin_password";

/// Where the image runs scripts on a first start, and the name of ours.
pub(crate) const INIT_SCRIPT_PATH: &str = "/docker-entrypoint-initdb.d/10-epistle-roles.sh";

/// Run by the image's entrypoint once, on an empty data directory, while
/// its temporary server listens on the socket only. It is inline in the
/// compose file, and compose interpolates `$NAME` in values, so it names
/// no shell variable: the passwords are read by psql from the secrets.
pub(crate) const INIT_SCRIPT: &str = "\
# epistle: create the role mail connects as, without superuser, as the owner
# of the epistle database only.
psql -X -v ON_ERROR_STOP=1 -U epistle_admin -d epistle <<'SQL'
\\set password `cat /run/secrets/epistle_db_password`
SELECT format('CREATE ROLE epistle LOGIN PASSWORD %L', :'password') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'epistle') \\gexec
SELECT format('ALTER ROLE epistle LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'password') \\gexec
ALTER DATABASE epistle OWNER TO epistle;
REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC;
SQL
";

/// Whether the role the stack connects as is a superuser (`t` or `f`).
pub(crate) const IS_SUPERUSER: &str = "SELECT rolsuper FROM pg_roles WHERE rolname = current_user";

/// Run in `db` with `sh -c` by `stack update` when [`IS_SUPERUSER`] says
/// `t`. A superuser cannot rename the role its own session logged in as,
/// so a temporary superuser does the work in one transaction and the new
/// admin drops it. A failure in the middle rolls back to `epistle` as it
/// was; running it again starts over.
pub(crate) const HARDEN_SCRIPT: &str = r#"set -e
export PGHOST=/var/run/postgresql PGDATABASE=epistle
admin="$(cat /run/secrets/epistle_db_admin_password)"
PGPASSWORD="$(cat /run/secrets/epistle_db_password)" psql -X -q -v ON_ERROR_STOP=1 -U epistle <<'SQL'
\set admin `cat /run/secrets/epistle_db_admin_password`
DROP ROLE IF EXISTS epistle_harden;
SELECT format('CREATE ROLE epistle_harden LOGIN SUPERUSER PASSWORD %L', :'admin') \gexec
SQL
PGPASSWORD="$admin" psql -X -q -v ON_ERROR_STOP=1 -1 -U epistle_harden <<'SQL'
\set admin `cat /run/secrets/epistle_db_admin_password`
\set password `cat /run/secrets/epistle_db_password`
ALTER ROLE epistle RENAME TO epistle_admin;
SELECT format('ALTER ROLE epistle_admin PASSWORD %L', :'admin') \gexec
SELECT format('CREATE ROLE epistle LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'password') \gexec
ALTER DATABASE epistle OWNER TO epistle;
SELECT format('ALTER TABLE %s OWNER TO epistle', c.oid::regclass) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND c.relowner = 'epistle_admin'::regrole \gexec
SELECT format('ALTER SEQUENCE %s OWNER TO epistle', c.oid::regclass) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S' AND c.relowner = 'epistle_admin'::regrole \gexec
SELECT format('ALTER FUNCTION %s OWNER TO epistle', p.oid::regprocedure) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proowner = 'epistle_admin'::regrole \gexec
SELECT format('ALTER TYPE %s OWNER TO epistle', t.oid::regtype) FROM pg_type t WHERE t.typnamespace = 'public'::regnamespace AND t.typowner = 'epistle_admin'::regrole AND t.typtype IN ('d', 'e', 'r') \gexec
REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC;
DO $$
BEGIN
	IF EXISTS (SELECT FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relowner = 'epistle_admin'::regrole)
		OR EXISTS (SELECT FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typowner = 'epistle_admin'::regrole AND typtype <> 'c')
		OR EXISTS (SELECT FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proowner = 'epistle_admin'::regrole) THEN
		RAISE EXCEPTION 'objects in public are still owned by epistle_admin';
	END IF;
END $$;
SQL
PGPASSWORD="$admin" psql -X -q -v ON_ERROR_STOP=1 -U epistle_admin -c 'DROP ROLE epistle_harden'
"#;

#[cfg(test)]
mod tests;
