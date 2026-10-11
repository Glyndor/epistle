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
		Ok(Some(command)) => in_container(config, command).await,
		Ok(None) => evaluate(database, NET_TIMEOUT).await,
		Err(error) => AreaReport::fail(error),
	}
}

/// Run `epistle check db --json` in the mail container and read its verdict.
async fn in_container(
	config: &crate::config::Config,
	command: std::process::Command,
) -> AreaReport {
	if let Err(error) = crate::cli::container_db::ensure_mail_running(config) {
		return AreaReport::fail(error);
	}
	let run = tokio::task::spawn_blocking(move || run_bounded(command, IN_CONTAINER_TIMEOUT));
	let stdout = match run.await {
		Ok(Ok(stdout)) => stdout,
		Ok(Err(error)) => return AreaReport::fail(error),
		Err(error) => return AreaReport::fail(format!("the database check task failed: {error}")),
	};
	parse_in_container(&stdout)
}

/// How long the check inside the container may take: the check itself is
/// bounded by its own 5 seconds, plus starting the exec.
const IN_CONTAINER_TIMEOUT: Duration = Duration::from_secs(20);

/// Run `command` to completion, killing it after `limit`; return its stdout.
fn run_bounded(mut command: std::process::Command, limit: Duration) -> Result<Vec<u8>, String> {
	use std::io::Read;
	let mut child = command
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::null())
		.spawn()
		.map_err(|error| format!("cannot run podup: {error}"))?;
	let deadline = std::time::Instant::now() + limit;
	loop {
		match child.try_wait() {
			Ok(Some(_)) => break,
			Ok(None) if std::time::Instant::now() < deadline => {
				std::thread::sleep(Duration::from_millis(100));
			}
			Ok(None) => {
				let _ = child.kill();
				let _ = child.wait();
				return Err("the database check in the mail container timed out".into());
			}
			Err(error) => return Err(format!("cannot wait for podup: {error}")),
		}
	}
	let mut stdout = Vec::new();
	if let Some(mut pipe) = child.stdout.take() {
		pipe.read_to_end(&mut stdout)
			.map_err(|error| format!("cannot read podup output: {error}"))?;
	}
	Ok(stdout)
}

/// The `db` entry of `epistle check db --json` as printed in the container.
fn parse_in_container(stdout: &[u8]) -> AreaReport {
	serde_json::from_slice::<std::collections::BTreeMap<String, AreaReport>>(stdout)
		.ok()
		.and_then(|mut areas| areas.remove("db"))
		.unwrap_or_else(|| {
			AreaReport::fail("the database check in the mail container gave no answer")
		})
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
