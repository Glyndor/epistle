//! The `db` check: when `[database]` is configured, the server's own
//! connection code reaches PostgreSQL and `SELECT 1` answers.

use std::time::Duration;

use super::report::{AreaReport, Level};
use super::{Ctx, NET_TIMEOUT};
use crate::config::Database;

/// Check the configured database.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let Some(database) = &config.database else {
		return AreaReport::ok("no [database] is configured");
	};
	// With the container stack the socket lives inside it: ask the mail
	// container, the only place the server itself connects from. The other
	// areas stay on the host, where the published ports are what matters.
	match crate::cli::container_db::exec_spec(
		config,
		&["check".into(), "db".into(), "--json".into()],
	) {
		Ok(Some(command)) => super::in_stack::run(config, command, "db", "database").await,
		Ok(None) => evaluate(database, NET_TIMEOUT).await,
		Err(error) => AreaReport::fail(error),
	}
}

/// Connect like the server does (but without applying migrations: a health
/// check must not change the schema), then run `SELECT 1`, all within `limit`.
async fn evaluate(database: &Database, limit: Duration) -> AreaReport {
	let attempt = async {
		let pool = crate::db::open(
			&database.url,
			database.tls,
			1,
			database.password_file.as_deref(),
		)
		.await
		.map_err(|error| error.to_string())?;
		let one: i32 = sqlx::query_scalar("SELECT 1")
			.fetch_one(&pool)
			.await
			.map_err(|error| format!("SELECT 1 failed: {error}"))?;
		pool.close().await;
		Ok::<i32, String>(one)
	};
	match tokio::time::timeout(limit, attempt).await {
		Ok(Ok(1)) => AreaReport::single(Level::Ok, "connected, SELECT 1 answered"),
		Ok(Ok(other)) => AreaReport::fail(format!("SELECT 1 returned {other}")),
		Ok(Err(error)) => AreaReport::fail(error),
		// sqlx keeps retrying a refused or silent server until its own (much
		// longer) acquire deadline, so both look the same from here.
		Err(_) => AreaReport::fail(format!(
			"cannot reach PostgreSQL within {limit:?} (refused, or no answer)"
		)),
	}
}

#[cfg(test)]
#[path = "db_area_tests.rs"]
mod tests;
