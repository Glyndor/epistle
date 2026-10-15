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

/// Run one SQL statement in the stack's `db` container and return its
/// unaligned, tuples-only output. `sql` must not contain a single quote: it
/// is single-quoted whole inside the shell script.
pub(in crate::cli) fn query(compose: &std::path::Path, sql: &str) -> Result<String, String> {
	if sql.contains('\'') {
		return Err("the query contains a single quote".to_string());
	}
	let script = format!(
		"PGPASSWORD=\"$(cat '{}')\" exec psql -Atq -h /var/run/postgresql -U '{}' -d '{}' -c '{sql}'",
		crate::cli::init::DATABASE_PASSWORD_FILE,
		crate::cli::init::DATABASE_USER,
		crate::cli::init::DATABASE_NAME,
	);
	let output = super::super::stack::build_command(
		"podup",
		compose,
		&["exec", "-T", "db", "sh", "-c", &script],
	)
	.stdin(Stdio::null())
	.output()
	.map_err(|error| format!("cannot run podup exec: {error}"))?;
	if !output.status.success() {
		return Err(format!(
			"the query in db failed ({}): {}",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		));
	}
	Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

impl Stack for Podup {
	fn compose(&mut self) -> Result<String, String> {
		std::fs::read_to_string(&self.compose)
			.map_err(|error| format!("cannot read {}: {error}", self.compose.display()))
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
		super::super::stack_health::wait_healthy("podup", &self.compose, service, DB_HEALTH)
	}

	fn counts(&mut self) -> Result<String, String> {
		query(&self.compose, COUNTS)
	}

	fn dump(&mut self) -> Result<Vec<u8>, String> {
		super::super::backup::collect_dump(&self.database, &self.data_dir)
			.map_err(|error| error.to_string())
	}

	fn keep_dump(&mut self, name: &str, sql: &[u8]) -> Result<PathBuf, String> {
		super::super::stack_dumps::keep(&self.data_dir, name, sql, SystemTime::now())
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
