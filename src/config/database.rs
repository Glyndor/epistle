//! Database configuration: the PostgreSQL backing for the antispam engine.

use serde::Deserialize;

/// The default connection-pool ceiling.
const fn default_max_connections() -> u32 {
	10
}

/// PostgreSQL connection settings. Present only when antispam features that
/// need persistence are in use.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
	/// libpq-style connection URL, e.g. `postgres://user:pass@host/db`.
	pub url: String,
	/// Maximum pooled connections.
	#[serde(default = "default_max_connections")]
	pub max_connections: u32,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn defaults_max_connections() {
		let db: Database = toml::from_str(r#"url = "postgres://localhost/mail""#).expect("parse");
		assert_eq!(db.max_connections, 10);
		assert_eq!(db.url, "postgres://localhost/mail");
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Database, _> =
			toml::from_str("url = \"postgres://x\"\nsurprise = true\n");
		assert!(result.is_err());
	}
}
