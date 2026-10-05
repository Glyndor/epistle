//! Database configuration: the PostgreSQL backing for the antispam engine.

use std::path::PathBuf;

use serde::Deserialize;

/// The default connection-pool ceiling.
const fn default_max_connections() -> u32 {
	10
}

/// How the `[database]` connection authenticates the PostgreSQL server when TLS
/// is not mandated by the URL. The default is the strictest option that still
/// works for a private deployment: TLS is required, and an absent or weaker
/// `sslmode` is rejected because libpq's `prefer` will silently fall back to
/// plaintext if the server does not offer TLS. The reputation, the Bayes
/// corpus and — with `directory = true` — the mail accounts travel over this
/// connection, so a silent downgrade is the worst kind of leak: the operator
/// never asked for it and never sees it happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseTls {
	/// Require TLS to the PostgreSQL server (the default). The URL must set
	/// `sslmode=require` (or `verify-ca` / `verify-full`); an absent or weaker
	/// `sslmode` is rejected. A Unix-domain socket in the URL is accepted as
	/// is because there is no network on the path to intercept.
	#[default]
	Require,
	/// Accept whatever `sslmode` the URL declares, including `disable`,
	/// because the PostgreSQL container is on an internal network with no
	/// gateway to the outside. The operator is asserting that. A passive
	/// eavesdropper on that wire is still a leak — the configuration review
	/// must take it as a given that the network is private.
	Insecure,
}

/// PostgreSQL connection settings. Present only when antispam features that
/// need persistence are in use.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
	/// libpq-style connection URL, e.g. `postgres://user:pass@host/db`.
	pub url: String,
	/// Maximum pooled connections.
	#[serde(default = "default_max_connections")]
	pub max_connections: u32,
	/// Load mail accounts from the SQL directory backend (the `directory_account`
	/// / `directory_address` tables) into the in-memory directory at startup and
	/// refresh them hourly. Off by default. Static config and dynamic accounts
	/// take precedence over SQL-sourced accounts on conflict.
	#[serde(default)]
	pub directory: bool,
	/// How the connection authenticates the PostgreSQL server. Defaults to
	/// [`DatabaseTls::Require`], which rejects any `sslmode` weaker than
	/// `require`; set to `insecure` to opt into a less-than-require `sslmode`
	/// (typically `disable` on an internal container network). See the enum
	/// for what each variant accepts and what it gives up.
	#[serde(default)]
	pub tls: DatabaseTls,
	/// Path to a file holding the PostgreSQL password, one trailing newline
	/// stripped. Read once at pool construction. Use this when the URL
	/// cannot carry the secret directly (the recommended container
	/// deployment: podup mounts the password as a read-only secret under
	/// `/run/secrets/<name>`, owned by the container's uid with mode
	/// `0400`). Refused when the URL already carries a password (two
	/// sources for one secret is ambiguous); the file must exist, be a
	/// regular file, and not be group- or world-accessible.
	#[serde(default)]
	pub password_file: Option<PathBuf>,
}

impl std::fmt::Debug for Database {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// The URL embeds the connection password; redact it whole. The
		// password_file field is a path on disk, so it is safe to print
		// verbatim (the contents are read at pool construction;
		// epistle never logs or prints the connection options).
		f.debug_struct("Database")
			.field("url", &"***")
			.field("max_connections", &self.max_connections)
			.field("directory", &self.directory)
			.field("tls", &self.tls)
			.field("password_file", &self.password_file)
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn defaults_max_connections() {
		let db: Database = toml::from_str(r#"url = "postgres://localhost/mail""#).expect("parse");
		assert_eq!(db.max_connections, 10);
		assert_eq!(db.url, "postgres://localhost/mail");
		assert!(!db.directory);
		assert_eq!(db.tls, DatabaseTls::Require);
	}

	#[test]
	fn parses_directory_flag() {
		let db: Database =
			toml::from_str("url = \"postgres://localhost/mail\"\ndirectory = true\n")
				.expect("parse");
		assert!(db.directory);
	}

	#[test]
	fn parses_insecure_tls_opt_in() {
		let db: Database = toml::from_str(
			r#"url = "postgres://localhost/mail"
tls = "insecure"
"#,
		)
		.expect("parse");
		assert_eq!(db.tls, DatabaseTls::Insecure);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Database, _> =
			toml::from_str("url = \"postgres://x\"\nsurprise = true\n");
		assert!(result.is_err());
	}

	#[test]
	fn rejects_unknown_tls_value() {
		// Only `require` (default) and `insecure` are accepted; a typo is not
		// silently coerced to one of them.
		let result: Result<Database, _> =
			toml::from_str("url = \"postgres://localhost/mail\"\ntls = \"maybe\"\n");
		assert!(result.is_err(), "unknown tls value must be rejected");
	}

	#[test]
	fn parses_password_file() {
		let db: Database = toml::from_str(
			r#"url = "postgres://epistle@%2Frun%2Fpostgresql/epistle"
password_file = "/run/secrets/epistle_db_password"
"#,
		)
		.expect("parse");
		assert_eq!(
			db.password_file,
			Some(PathBuf::from("/run/secrets/epistle_db_password"))
		);
	}

	#[test]
	fn password_file_defaults_to_none() {
		let db: Database = toml::from_str(r#"url = "postgres://localhost/mail""#).expect("parse");
		assert!(db.password_file.is_none());
	}
}
