//! The two halves of `epistle stack rollback`: root swaps the binary, the
//! service account restores the database.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use super::{KEPT, migrations_in_dump, schema_moved};
use crate::config::Config;

/// The installed binary the rollback replaces.
const INSTALLED: &str = "/usr/bin/epistle";

/// `sudo epistle stack rollback [--to VERSION]`.
pub(in crate::cli) fn run_as_root(
	config_path: &Path,
	to: Option<&str>,
	yes: bool,
	json: bool,
) -> ExitCode {
	match as_root(config_path, to, yes) {
		Ok(summary) => {
			eprintln!("epistle: {summary}");
			if !json {
				return ExitCode::SUCCESS;
			}
			let result = serde_json::json!({
				"result": "done", "action": "rollback", "summary": summary,
			});
			crate::cli::json_out::print(&mut std::io::stdout().lock(), &result)
		}
		Err(Stop::Declined(code)) => code,
		Err(Stop::Failed(error)) => {
			crate::cli::style::error(format_args!("stack rollback failed: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// Why the root half stopped.
enum Stop {
	/// The operator did not confirm; the prompt's exit code.
	Declined(ExitCode),
	/// A step failed.
	Failed(String),
}

impl From<String> for Stop {
	fn from(error: String) -> Self {
		Stop::Failed(error)
	}
}

impl From<&str> for Stop {
	fn from(error: &str) -> Self {
		Stop::Failed(error.to_string())
	}
}

fn as_root(config_path: &Path, to: Option<&str>, yes: bool) -> Result<String, Stop> {
	// SAFETY: geteuid takes no arguments and cannot fail.
	if unsafe { libc::geteuid() } != 0 {
		return Err(
			"it replaces /usr/bin/epistle, so run it as root: sudo epistle stack rollback".into(),
		);
	}
	let config = Config::load(config_path).map_err(|error| Stop::Failed(error.to_string()))?;
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	let user = crate::cli::rootless::lookup_user()
		.map_err(|error| format!("cannot look up glyndor-epistle: {error}"))?
		.ok_or("there is no glyndor-epistle account")?;
	let current = env!("CARGO_PKG_VERSION");
	let store = super::store::Store::open(Path::new(KEPT)).map_err(|error| {
		format!("cannot open {KEPT} ({error}); legacy copies in the service directory are ignored; rollback is unavailable until an upgrade saves a trusted binary")
	})?;
	let (chosen, mut binary) = store.select(current, to)?;
	let version = chosen.trim_start_matches("epistle-").to_string();
	crate::cli::prompt::confirm_destructive(
		&super::action(&version),
		&super::question(current, &version),
		yes,
	)
	.map_err(Stop::Declined)?;
	eprintln!("epistle: rolling back from {current} to {version}");
	let exe =
		std::env::current_exe().map_err(|error| format!("cannot find this binary: {error}"))?;
	let database = crate::cli::rootless::account_command(&user, &exe)
		.arg("stack")
		.arg("--config")
		.arg(config_path)
		.arg("rollback-db")
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::inherit())
		.output();
	let restored = match &database {
		Ok(output) if output.status.success() => {
			super::restored(&String::from_utf8_lossy(&output.stdout))
		}
		_ => {
			let _ = start_mail(&user, &compose);
			return Err(Stop::Failed(format!(
				"the database step failed (see above); {INSTALLED} was not changed and mail was started again on {current}"
			)));
		}
	};
	if let Err(error) = super::store::install(&mut binary, Path::new(INSTALLED)) {
		let _ = start_mail(&user, &compose);
		return Err(Stop::Failed(format!(
			"cannot put the {version} binary in place ({error}); mail was started again on {current}, \
			 and if the database was restored, run `sudo epistle stack rollback` again"
		)));
	}
	start_mail(&user, &compose)?;
	Ok(super::summary(current, &version, restored))
}

/// `podup start mail` as the account, with the operator's override.
fn start_mail(user: &crate::cli::rootless::ServiceUser, compose: &Path) -> Result<(), String> {
	let podup = crate::cli::stack::build_command("podup", compose, &["start", "mail"]);
	let status = crate::cli::rootless::account_command(user, "podup")
		.args(podup.get_args())
		.stdout(crate::cli::json_out::child_stdout())
		.status()
		.map_err(|error| format!("cannot start mail: {error}"))?;
	if status.success() {
		Ok(())
	} else {
		Err(format!("`podup start mail` exited with {status}"))
	}
}

/// `stack rollback-db`, as the service account: stop mail and, when the
/// schema moved past the dump `stack update` took, restore that dump.
pub(in crate::cli) fn restore_db(config: &Config, compose: &Path, podup: &str) -> ExitCode {
	match restore(config, compose, podup) {
		Ok(line) => {
			eprintln!("epistle: {line}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			crate::cli::style::error(error);
			ExitCode::FAILURE
		}
	}
}

fn restore(config: &Config, compose: &Path, podup: &str) -> Result<String, String> {
	if crate::cli::stack::run_sequence(podup, compose, &[&["stop", "mail"]]) != ExitCode::SUCCESS {
		return Err("cannot stop mail".into());
	}
	let has_db = std::fs::read(compose)
		.ok()
		.and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
		.is_some_and(|value| value["services"].get("db").is_some());
	let Some(database) = config.database.as_ref().filter(|_| has_db) else {
		return Ok("the stack has no database of its own; nothing to restore".into());
	};
	let version = env!("CARGO_PKG_VERSION");
	let dump = crate::cli::stack_dumps::newest(&config.data_dir, &format!("pre-{version}-"))
		.ok_or_else(|| {
			format!(
				"there is no dump from before {version} under {}; an older binary may not read \
				 this schema, so nothing was rolled back",
				crate::cli::stack_dumps::dir(&config.data_dir).display()
			)
		})?;
	let mut sql = String::new();
	std::fs::File::open(&dump)
		.map(flate2::read::GzDecoder::new)
		.and_then(|mut decoder| decoder.read_to_string(&mut sql))
		.map_err(|error| format!("cannot read {}: {error}", dump.display()))?;
	let current: std::collections::BTreeSet<i64> =
		crate::cli::db_upgrade::query(compose, "SELECT version FROM _sqlx_migrations ORDER BY 1")?
			.lines()
			.filter_map(|line| line.trim().parse().ok())
			.collect();
	if !schema_moved(&migrations_in_dump(&sql), &current) {
		return Ok(format!(
			"the schema has not moved past {}; the database is kept as it is",
			dump.display()
		));
	}
	crate::cli::backup::load_dump(database, &config.data_dir, sql.as_bytes())
		.map_err(|error| format!("restoring {} failed: {error}", dump.display()))?;
	// The root half reads this line to word its closing message.
	println!("{}", super::RESTORED);
	Ok(format!("the database is back to {}", dump.display()))
}
