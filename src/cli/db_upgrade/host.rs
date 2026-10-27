//! The real [`Stack`] for `epistle db upgrade`: podup against the generated
//! compose file, and the backup code's dump and load.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use super::flow::Stack;
use crate::config::{Config, Database};

/// Exact row counts of every table, one `schema.table=count` per table,
/// joined with commas. Written with dollar quotes only, so the shell
/// script around it can single-quote it whole.
const COUNTS: &str = "SELECT coalesce(string_agg(format($f$%I.%I=%s$f$, table_schema, table_name, \
	(xpath($x$/row/c/text()$x$, query_to_xml(format($q$SELECT count(*) AS c FROM %I.%I$q$, \
	table_schema, table_name), false, true, $e$$e$)))[1]::text), $c$,$c$ ORDER BY table_schema, \
	table_name), $n$$n$) FROM information_schema.tables WHERE table_type = $t$BASE TABLE$t$ \
	AND table_schema NOT IN ($p$pg_catalog$p$, $i$information_schema$i$)";

/// How long the new major may take to report healthy.
const DB_HEALTH: Duration = Duration::from_secs(180);

pub(super) struct Podup {
	compose: PathBuf,
	data_dir: PathBuf,
	database: Database,
}

impl Podup {
	pub(super) fn new(config: &Config) -> Result<Self, String> {
		let compose = super::super::stack::compose_path(&config.data_dir);
		if !compose.exists() {
			return Err(format!(
				"{} does not exist; there is no stack to upgrade",
				compose.display()
			));
		}
		let database = config
			.database
			.clone()
			.ok_or("the config has no [database]; the stack runs without PostgreSQL")?;
		Ok(Self {
			compose,
			data_dir: config.data_dir.clone(),
			database,
		})
	}

	fn command(&self, args: &[&str]) -> std::process::Command {
		super::super::stack::build_command("podup", &self.compose, args)
	}
}

/// The `podup exec` that runs one SQL statement in the stack's `db`
/// container through `program`. `sql` must not contain a single quote: it
/// is single-quoted whole inside the shell script.
fn query_command(
	program: &str,
	compose: &std::path::Path,
	sql: &str,
) -> Result<std::process::Command, String> {
	if sql.contains('\'') {
		return Err("the query contains a single quote".to_string());
	}
	let script = format!(
		"PGPASSWORD=\"$(cat '{}')\" exec psql -Atq -h /var/run/postgresql -U '{}' -d '{}' -c '{sql}'",
		crate::cli::init::DATABASE_PASSWORD_FILE,
		crate::cli::init::DATABASE_USER,
		crate::cli::init::DATABASE_NAME,
	);
	let mut command = super::super::stack::build_command(
		program,
		compose,
		&["exec", "-T", "db", "sh", "-c", &script],
	);
	command.stdin(Stdio::null());
	Ok(command)
}

/// What a finished query printed, or why it failed.
fn query_answer(output: &std::process::Output) -> Result<String, String> {
	if !output.status.success() {
		return Err(format!(
			"the query in db failed ({}): {}",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		));
	}
	Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run one SQL statement in the stack's `db` container and return its
/// unaligned, tuples-only output, waiting as long as it takes. `sql` must
/// not contain a single quote: it is single-quoted whole inside the shell
/// script.
pub(in crate::cli) fn query(compose: &std::path::Path, sql: &str) -> Result<String, String> {
	let output = query_command("podup", compose, sql)?
		.output()
		.map_err(|error| format!("cannot run podup exec: {error}"))?;
	query_answer(&output)
}

/// [`query`] that gives up after `limit`: the child is killed and the
/// query is reported as not answered. For a command that only looks, so a
/// stuck container cannot hold the terminal.
pub(in crate::cli) fn query_within(
	compose: &std::path::Path,
	sql: &str,
	limit: Duration,
) -> Result<String, String> {
	query_within_program("podup", compose, sql, limit)
}

/// The most of a query's output that is kept; the rest is read and dropped so
/// the child never blocks on a full pipe.
const KEEP_OUTPUT: usize = 1 << 20;

/// Read `pipe` to its end, keeping the first [`KEEP_OUTPUT`] bytes and one
/// more, so the caller can tell that there was more.
fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
	std::thread::spawn(move || {
		let mut kept = Vec::new();
		let mut chunk = [0_u8; 16 * 1024];
		while let Ok(read) = pipe.read(&mut chunk) {
			if read == 0 {
				break;
			}
			let room = (KEEP_OUTPUT + 1).saturating_sub(kept.len());
			kept.extend_from_slice(&chunk[..read.min(room)]);
		}
		kept
	})
}

fn query_within_program(
	program: &str,
	compose: &std::path::Path,
	sql: &str,
	limit: Duration,
) -> Result<String, String> {
	use std::os::unix::process::CommandExt;
	// Its own process group, so stopping the query stops what `podup` started
	// (`podman exec`, `psql`) and not only `podup`.
	let mut child = query_command(program, compose, sql)?
		.process_group(0)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.map_err(|error| format!("cannot run podup exec: {error}"))?;
	let stdout = child.stdout.take().map(drain);
	let stderr = child.stderr.take().map(drain);
	let deadline = std::time::Instant::now() + limit;
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if std::time::Instant::now() >= deadline => {
				if let Ok(pid) = i32::try_from(child.id()) {
					// SAFETY: signalling the process group this function created.
					unsafe { libc::kill(-pid, libc::SIGKILL) };
				}
				let _ = child.kill();
				let _ = child.wait();
				return Err(format!("the query in db did not answer within {limit:?}"));
			}
			Ok(None) => std::thread::sleep(Duration::from_millis(20)),
			Err(error) => return Err(format!("cannot wait for podup exec: {error}")),
		}
	};
	let take = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| {
		handle
			.and_then(|handle| handle.join().ok())
			.unwrap_or_default()
	};
	let (stdout, stderr) = (take(stdout), take(stderr));
	if status.success() && stdout.len() > KEEP_OUTPUT {
		return Err("the answer of the query is larger than 1 MiB".to_string());
	}
	query_answer(&std::process::Output {
		status,
		stdout,
		stderr,
	})
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;

impl Stack for Podup {
	fn compose(&mut self) -> Result<String, String> {
		// The upgrade holds the common lock for minutes, so this read goes
		// through the reader that refuses a fifo instead of waiting for a
		// writer that may never come and holding the lock while it does.
		let bytes = crate::cli::init::compose_read::read(&self.compose)?.ok_or_else(|| {
			format!(
				"cannot read {}: there is no such file",
				self.compose.display()
			)
		})?;
		String::from_utf8(bytes)
			.map_err(|_| format!("{} is not valid UTF-8", self.compose.display()))
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		crate::storage::write_secret(&self.compose, text.as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", self.compose.display()))
	}

	fn podup(&mut self, args: &[&str]) -> Result<(), String> {
		let status = self
			.command(args)
			.stdin(Stdio::null())
			.stdout(crate::cli::json_out::child_stdout())
			.status()
			.map_err(|error| format!("cannot run podup: {error}"))?;
		if status.success() {
			Ok(())
		} else {
			Err(format!("`podup {}` exited with {status}", args.join(" ")))
		}
	}

	fn wait_healthy(&mut self, service: &str) -> Result<(), String> {
		super::super::stack::health::wait_healthy("podup", &self.compose, service, DB_HEALTH)
	}

	fn counts(&mut self) -> Result<String, String> {
		query(&self.compose, COUNTS)
	}

	fn dump(&mut self) -> Result<Vec<u8>, String> {
		super::super::backup::collect_dump(&self.database, &self.data_dir)
			.map_err(|error| error.to_string())
	}

	fn keep_dump(&mut self, name: &str, sql: &[u8]) -> Result<PathBuf, String> {
		super::super::stack::dumps::keep(&self.data_dir, name, sql, SystemTime::now())
			.map_err(|error| format!("cannot keep the dump: {error}"))
	}

	fn load(&mut self, sql: &[u8]) -> Result<(), String> {
		super::super::backup::load_dump(&self.database, &self.data_dir, sql)
			.map_err(|error| error.to_string())
	}

	fn log(&mut self, line: &str) {
		eprintln!("epistle: {line}");
	}
}
