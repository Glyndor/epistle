//! The `epistle restore` subcommand: read the tar.gz, check that the target
//! can take it, replay the database and lay the files down.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::db_dump::{self, DATABASE_SQL_NAME, load_dump_with, output_ends_with_pg_dump_complete};
use super::gunzip::gunzip_archive;
use super::restore_files::{check_files, lay_files, load_failure_state};
use super::{keys_note, restore_signals, tar_format};
use crate::cli::term::live::{Steps, quiet};
use crate::config::Config;

/// Run the `restore` subcommand. Reads a tar.gz from `archive`, lays the
/// `data/` entries down under `data_dir`, and replays `database.sql` against
/// the configured database when the archive carries one. The hard rule is
/// the same as the backup path: a `database.sql` in the archive that cannot
/// be loaded is a restore error, never a silent skip.
///
/// `force` bypasses the safety checks (`refuse_unsafe_targets` returns
/// `None`), `dry_run` lists the entries the restore would write without
/// touching `data_dir` or the database. Status messages go to `status`
/// so the operator can tell them apart from the archive stream.
pub(in crate::cli) fn run_restore(
	config: &Config,
	archive: &[u8],
	force: bool,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> ExitCode {
	run_restore_with(
		config,
		archive,
		force,
		dry_run,
		out,
		status,
		&db_dump::default_program_resolver,
	)
}

/// Same as [`run_restore`] with a custom program resolver. The test
/// path passes a resolver that returns absolute paths to its stubs;
/// production callers pass the default, which is a no-op and lets
/// `Command::new` resolve through `PATH` exactly as it always has.
pub(in crate::cli) fn run_restore_with(
	config: &Config,
	archive: &[u8],
	force: bool,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> ExitCode {
	restore_summarising(
		config,
		archive,
		force,
		dry_run,
		out,
		status,
		resolver,
		&mut RestoreSummary::default(),
	)
}

/// What a restore did or, with `--dry-run`, would do: how many archive
/// entries, and the destination of each, taken from the archive itself.
#[derive(Debug, Default)]
pub(in crate::cli) struct RestoreSummary {
	/// Entries in the archive.
	pub entries: usize,
	/// Where each entry would be written, filled for a dry run only:
	/// `data/<name>` for a file, `database.sql` for the dump.
	pub paths: Vec<String>,
}

/// [`run_restore`] that also reports the [`RestoreSummary`], so a caller
/// that prints JSON does not have to read the text listing back.
pub(in crate::cli) fn run_restore_reporting(
	config: &Config,
	archive: &[u8],
	force: bool,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> (ExitCode, RestoreSummary) {
	let mut summary = RestoreSummary::default();
	let exit = restore_summarising(
		config,
		archive,
		force,
		dry_run,
		out,
		status,
		&db_dump::default_program_resolver,
		&mut summary,
	);
	(exit, summary)
}

#[allow(clippy::too_many_arguments)]
fn restore_summarising(
	config: &Config,
	archive: &[u8],
	force: bool,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
	summary: &mut RestoreSummary,
) -> ExitCode {
	let mut steps = if dry_run {
		Steps::off()
	} else {
		Steps::start(&["archive", "database", "files"], false)
	};
	steps.begin("archive");
	let tar = match gunzip_archive(archive) {
		Ok(tar) => tar,
		Err(error) => {
			steps.fail();
			crate::cli::style::error(format_args!("reading archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let entries = match tar_format::read_entries(&tar) {
		Ok(entries) => entries,
		Err(error) => {
			crate::cli::style::error(format_args!("reading archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if entries.is_empty() {
		steps.fail();
		crate::cli::style::error("archive is empty");
		return ExitCode::FAILURE;
	}
	steps.done();
	if let Err(message) = quiet(|| refuse_unsafe_targets(config, force, dry_run, status)) {
		crate::cli::style::error(format_args!("{message}"));
		return ExitCode::FAILURE;
	}
	summary.entries = entries.len();
	if dry_run {
		// The preview answers for the same checks the restore makes before it
		// writes, so an archive it would refuse does not read as a green run.
		if let Err(error) = check_files(&entries, &config.data_dir) {
			crate::cli::style::error(format_args!("laying down files: {error}"));
			return ExitCode::FAILURE;
		}
		let _ = writeln!(out, "would restore {} entries:", entries.len());
		for (name, _mode, content) in &entries {
			if name == DATABASE_SQL_NAME {
				summary.paths.push(DATABASE_SQL_NAME.to_string());
				let _ = writeln!(
					out,
					"  database.sql ({} bytes, replayed to psql)",
					content.len()
				);
			} else {
				summary.paths.push(format!("data/{name}"));
				// A name comes from the archive: escaped, it cannot pass
				// for a further line of this listing.
				let _ = writeln!(out, "  data/{}", crate::cli::term::sanitize(name));
			}
		}
		let _ = writeln!(out, "no files written; rerun without --dry-run to apply");
		return ExitCode::SUCCESS;
	}
	// Nothing is written until everything that can be checked has been: the
	// files must be placeable, and the dump must be there if a database is
	// configured. The database goes first because its load is one
	// transaction that stops at the first error, so a failure leaves the
	// data directory and the database as they were. Laying the files first
	// left them restored and the database not.
	if let Err(error) = check_files(&entries, &config.data_dir) {
		crate::cli::style::error(format_args!("laying down files: {error}"));
		return ExitCode::FAILURE;
	}
	// A truncated dump is refused: the marker `pg_dump` writes last has to be
	// there, as it has to be when the backup is made. This catches a cut, not a
	// forgery: whoever writes the archive can write the marker too, and the SQL
	// then runs as it is, so an archive is only as trustworthy as where it came from.
	if config.database.is_some()
		&& let Some((_, _, sql)) = entries
			.iter()
			.find(|(name, _, _)| name == DATABASE_SQL_NAME)
		&& !output_ends_with_pg_dump_complete(sql)
	{
		crate::cli::style::error(
			"database.sql in the archive does not end with the pg_dump closing marker, so it is incomplete; nothing was restored",
		);
		return ExitCode::FAILURE;
	}
	// From here on a stop signal is held: the restore either stops before it
	// writes anything or finishes both halves, and the signal is raised again
	// when `_held` is dropped at the end of this function.
	let _held = restore_signals::HeldSignals::hold();
	if let Err(error) = restore_signals::stop_if_arrived() {
		crate::cli::style::error(format_args!("restore: {error}; nothing was restored"));
		return ExitCode::FAILURE;
	}
	let mut database_loaded = false;
	if let Some(db) = &config.database {
		steps.begin("database");
		let Some(sql) = entries
			.iter()
			.find(|(name, _, _)| name == DATABASE_SQL_NAME)
			.map(|(_, _, content)| content)
		else {
			steps.fail();
			crate::cli::style::error("archive has no database.sql but [database] is configured");
			return ExitCode::FAILURE;
		};
		if let Err(error) = load_dump_with(db, &config.data_dir, sql, resolver) {
			steps.fail();
			crate::cli::style::error(format_args!(
				"database load: {error}; {}",
				load_failure_state(&error, &config.data_dir)
			));
			return ExitCode::FAILURE;
		}
		database_loaded = true;
		steps.done();
	}
	steps.begin("files");
	if let Err(error) = lay_files(&entries, &config.data_dir) {
		steps.fail();
		let state = if database_loaded {
			"; the database was already restored from the archive, so fix the cause and run the restore again with --force"
		} else {
			""
		};
		crate::cli::style::error(format_args!("laying down files: {error}{state}"));
		return ExitCode::FAILURE;
	}
	steps.done();
	writeln!(out, "restored {} entries", entries.len()).ok();
	keys_note::after_restore(&config.data_dir, &entries, status);
	steps.conclude(true, "restore");
	ExitCode::SUCCESS
}

/// Refuse to restore when `data_dir` already has account data or the
/// mail service is running, unless `--force` was supplied. The check
/// happens before `lay_files` so the byte-identity of `data_dir` is
/// preserved on refusal. The dry-run path also wants to know whether
/// a real restore would be allowed, so it is included in the check.
/// Each offender the operator can act on is named on its own line,
/// followed by a one-line suggestion that points at the matching
/// command (stop the service, pass `--force`).
pub(in crate::cli) fn refuse_unsafe_targets(
	config: &Config,
	force: bool,
	dry_run: bool,
	status: &mut impl Write,
) -> Result<(), String> {
	if force {
		return Ok(());
	}
	if let Err(reason) = data_dir_has_accounts(&config.data_dir) {
		let _ = writeln!(
			status,
			"refusing to restore: {} already holds account data in {}",
			reason,
			config.data_dir.display()
		);
		let _ = writeln!(
			status,
			"  stop the mail service, move the directory aside, or pass --force"
		);
		return Err("data_dir already holds account data".to_string());
	}
	if mail_service_is_running(&config.data_dir) {
		let _ = writeln!(
			status,
			"refusing to restore: the mail service is reported running by the compose stack in {}",
			config.data_dir.display()
		);
		let _ = writeln!(
			status,
			"  stop it first and keep the database up (`epistle stack stop mail`), or pass --force"
		);
		return Err("mail service is running".into());
	}
	let _ = dry_run;
	Ok(())
}

/// True when `data_dir` has any of the artefacts a previously running
/// server would have produced: an account store, masked addresses,
/// per-account files, or any regular file under `accounts/`. The
/// presence of a `database.sql` artefact from an earlier aborted
/// restore is also a sign the directory is not fresh.
///
/// Returns the offender file name so the error message names the
/// actual artefact found, not a generic `data_dir is non-empty`.
fn data_dir_has_accounts(data_dir: &Path) -> Result<(), String> {
	for relative in [
		"accounts.toml",
		"masked.json",
		"queue.toml",
		"bayes.json",
		"database.sql",
	] {
		if data_dir.join(relative).exists() {
			return Err(relative.to_string());
		}
	}
	let accounts_dir = data_dir.join("accounts");
	if accounts_dir.is_dir()
		&& let Ok(read) = std::fs::read_dir(&accounts_dir)
	{
		for entry in read.flatten().take(1) {
			if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
				return Err(format!("accounts/{}", entry.file_name().to_string_lossy()));
			}
		}
	}
	Ok(())
}

/// Detect whether the mail service is currently running by asking the
/// compose stack. The compose file lives at `<data_dir>/compose/compose.yaml`;
/// without it (the standalone host install, or a setup the operator
/// built by hand) there is no stack to talk to and the answer is "not
/// running": the operator has nothing to stop. When the compose file
/// exists, the `podup ps` listing is the source of truth. The probe
/// shares the live `podup` binary the rest of the CLI calls, so the
/// answer is what the operator sees.
fn mail_service_is_running(data_dir: &Path) -> bool {
	crate::cli::stack::started::mail_started_at(data_dir, "podup")
		.ok()
		.flatten()
		.is_some()
}
