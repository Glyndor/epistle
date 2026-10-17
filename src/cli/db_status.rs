//! `epistle db status`: what the stack's PostgreSQL says about itself, from
//! one read-only query run in its container. Nothing is changed and no
//! table is read: the numbers come from the server's own catalogues.

use std::process::ExitCode;
use std::time::Duration;

use serde::Serialize;

use super::term::sanitize;
use crate::config::Config;

/// How long the query may take before the command gives up.
const QUERY_LIMIT: Duration = Duration::from_secs(15);

/// One `SELECT`, in dollar quotes because the query runner single-quotes
/// it whole: the server version, the size of the database, the number of
/// user tables, the connections to this database and the connection limit.
const QUERY: &str = "SELECT current_setting($v$server_version$v$), \
	pg_database_size(current_database()), \
	(SELECT count(*) FROM pg_stat_user_tables), \
	(SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()), \
	current_setting($m$max_connections$m$)";

/// The answer, as `db status --json` prints it.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct Status {
	database: &'static str,
	version: String,
	size_bytes: u64,
	tables: u64,
	connections: u64,
	max_connections: u64,
}

/// The longest version string accepted from the server.
const MAX_VERSION: usize = 64;

/// Read the five fields of the answer, or say what was wrong with it.
fn parse(answer: &str) -> Result<Status, String> {
	let unexpected = || {
		format!(
			"unexpected answer from the database: {:?}",
			sanitize(&crate::util::address_reason::shorten(answer))
		)
	};
	let fields: Vec<&str> = answer.trim().split('|').collect();
	let [version, size, tables, connections, max] = fields[..] else {
		return Err(unexpected());
	};
	let number = |text: &str| -> Result<u64, String> {
		if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
			return Err(unexpected());
		}
		text.parse().map_err(|_| unexpected())
	};
	if version.is_empty() || version.chars().count() > MAX_VERSION {
		return Err(unexpected());
	}
	Ok(Status {
		database: crate::cli::init::DATABASE_NAME,
		version: version.to_string(),
		size_bytes: number(size)?,
		tables: number(tables)?,
		connections: number(connections)?,
		max_connections: number(max)?,
	})
}

/// Run `db status`.
pub(super) fn run(config: &Config, json: bool) -> ExitCode {
	if config.database.is_none() {
		return super::exit::policy(
			"the config has no [database]; the stack runs without PostgreSQL",
		);
	}
	let compose = super::stack::compose_path(&config.data_dir);
	if !compose.exists() {
		return super::exit::policy(format_args!(
			"{} does not exist; there is no stack to query",
			compose.display()
		));
	}
	let status = super::db_upgrade::query_within(&compose, QUERY, QUERY_LIMIT)
		.and_then(|answer| parse(&answer));
	let status = match status {
		Ok(status) => status,
		Err(error) => {
			super::style::error(format_args!("cannot read the database status: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut out = std::io::stdout().lock();
	if json {
		return match serde_json::to_value(&status) {
			Ok(value) => super::json_out::print(&mut out, &value),
			Err(error) => {
				super::style::error(format_args!("writing JSON: {error}"));
				ExitCode::FAILURE
			}
		};
	}
	use std::io::Write;
	let written = write!(
		out,
		"database\t{}\nversion\t{}\nsize_bytes\t{}\ntables\t{}\nconnections\t{} of {}\n",
		status.database,
		sanitize(&status.version),
		status.size_bytes,
		status.tables,
		status.connections,
		status.max_connections,
	);
	match written {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(format_args!("writing output: {error}"));
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "db_status_tests.rs"]
mod tests;
