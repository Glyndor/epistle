//! The `epistle backup` and `epistle restore` subcommands.
//!
//! The full module used to live in a single `backup.rs`. The dump
//! (and replay) of the database split out into `db_dump.rs` to keep
//! this file under the per-file 500-code-line cap; the test
//! modules are split into the same-named `*_tests_<topic>.rs`
//! siblings and re-pulled in with `#[path]` so each compile unit
//! stays small.

mod db_dump;
mod keys_note;
mod restore_files;
mod restore_signals;
mod tar_format;

use restore_files::{check_files, lay_files, load_failure_state};

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::term::live::{Steps, quiet};
use crate::config::{BlobBackendConfig, Config};

use db_dump::{
	DATABASE_SQL_NAME, collect_dump_with, load_dump_with, output_ends_with_pg_dump_complete,
};

/// Run the `backup` subcommand. Builds the entries, writes the tar.gz, emits
/// warnings. A configured database whose dump cannot be taken is a hard
/// error: an archive without the database is worse than no archive, because
/// the operator only finds out at restore time that the accounts and the
/// antispam state are gone.
pub(super) fn run(config: &Config, out: &mut impl Write, warnings: &mut impl Write) -> ExitCode {
	run_with(config, out, warnings, &db_dump::default_program_resolver)
}

/// Same as [`run`] with a custom program resolver. Tests use the
/// resolver to point `pg_dump` and `psql` at a stub in a tempdir
/// without touching the process `PATH`; production callers pass the
/// default, which is a no-op.
pub(super) fn run_with(
	config: &Config,
	out: &mut impl Write,
	warnings: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> ExitCode {
	let mut steps = Steps::start(&["files", "database", "archive"], false);
	steps.begin("files");
	let mut entries = match collect_files(&config.data_dir) {
		Ok(entries) => entries,
		Err(error) => {
			steps.fail();
			super::style::error(format_args!("reading data dir: {error}"));
			return ExitCode::FAILURE;
		}
	};
	steps.done();
	if let Some(db) = &config.database {
		steps.begin("database");
		let dump = match collect_dump_with(db, &config.data_dir, resolver) {
			Ok(dump) => dump,
			Err(error) => {
				steps.fail();
				super::style::error(format_args!("database dump: {error}"));
				return ExitCode::FAILURE;
			}
		};
		entries.push((DATABASE_SQL_NAME.to_string(), 0o644, dump));
		steps.done();
	}
	steps.begin("archive");
	let archive = match tar_gz(&entries) {
		Ok(archive) => archive,
		Err(error) => {
			steps.fail();
			super::style::error(format_args!("building archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if quiet(|| out.write_all(&archive).and_then(|()| out.flush())).is_err() {
		return ExitCode::FAILURE;
	}
	steps.done();
	warn_externally_referenced(config, &entries.len(), warnings);
	keys_note::after_backup(&config.data_dir, warnings);
	let summary = format!("backed up {} files for this instance", entries.len());
	if steps.is_live() {
		steps.conclude(true, &summary);
	} else {
		eprintln!("{summary}");
	}
	ExitCode::SUCCESS
}

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
pub(super) fn run_restore(
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
pub(super) fn run_restore_with(
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
			super::style::error(format_args!("reading archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let entries = match tar_format::read_entries(&tar) {
		Ok(entries) => entries,
		Err(error) => {
			super::style::error(format_args!("reading archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if entries.is_empty() {
		steps.fail();
		super::style::error("archive is empty");
		return ExitCode::FAILURE;
	}
	steps.done();
	if let Err(message) = quiet(|| refuse_unsafe_targets(config, force, dry_run, status)) {
		super::style::error(format_args!("{message}"));
		return ExitCode::FAILURE;
	}
	summary.entries = entries.len();
	if dry_run {
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
				let _ = writeln!(out, "  data/{}", super::term::sanitize(name));
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
		super::style::error(format_args!("laying down files: {error}"));
		return ExitCode::FAILURE;
	}
	// A dump cut short never reaches the database: the marker `pg_dump` writes
	// last has to be there, as it has to be when the backup is made.
	if config.database.is_some()
		&& let Some((_, _, sql)) = entries
			.iter()
			.find(|(name, _, _)| name == DATABASE_SQL_NAME)
		&& !output_ends_with_pg_dump_complete(sql)
	{
		super::style::error(
			"database.sql in the archive does not end with the pg_dump closing marker, so it is incomplete; nothing was restored",
		);
		return ExitCode::FAILURE;
	}
	// From here on a stop signal is held: the restore either stops before it
	// writes anything or finishes both halves, and the signal is raised again
	// when `_held` is dropped at the end of this function.
	let _held = restore_signals::HeldSignals::hold();
	if let Err(error) = restore_signals::stop_if_arrived() {
		super::style::error(format_args!("restore: {error}; nothing was restored"));
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
			super::style::error("archive has no database.sql but [database] is configured");
			return ExitCode::FAILURE;
		};
		if let Err(error) = load_dump_with(db, &config.data_dir, sql, resolver) {
			steps.fail();
			super::style::error(format_args!(
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
		super::style::error(format_args!("laying down files: {error}{state}"));
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
	super::stack::started::mail_started_at(data_dir, "podup")
		.ok()
		.flatten()
		.is_some()
}

/// Gunzip an archive and return its raw tar bytes. Tiny wrapper over
/// `flate2::read::GzDecoder` so the call site in `run_restore` surfaces
/// any decode error with a real `io::Error` rather than a panic.
fn gunzip_archive(data: &[u8]) -> std::io::Result<Vec<u8>> {
	use std::io::Read;
	let mut decoder = flate2::read::GzDecoder::new(data);
	let mut out = Vec::new();
	decoder.read_to_end(&mut out)?;
	Ok(out)
}

/// Write to `warnings` a description of every path the configuration references
/// but the archive does not contain. The archive covers `data_dir` only; keys
/// for TLS, DKIM, ARC, the at-rest message encryption, the S3 blob backend and
/// the DNS provider are typically kept outside that tree (by design, for
/// encryption-at-rest) and have to be backed up separately.
///
/// Two blocks when the at-rest key is involved: the general "outside data_dir"
/// list, and a separate, more prominent block that calls out the encryption key
/// because losing it makes the mail content in the archive permanently
/// unreadable.
fn warn_externally_referenced(config: &Config, archived: &usize, warnings: &mut impl Write) {
	let mut entries: Vec<String> = Vec::new();
	let mut encryption_key: Vec<String> = Vec::new();

	if let Some(tls) = &config.tls {
		entries.push(format!("[tls] cert_file = {}", tls.cert_file.display()));
		entries.push(format!("[tls] key_file = {}", tls.key_file.display()));
		if let Some(ca) = &tls.client_ca {
			entries.push(format!("[tls] client_ca = {}", ca.display()));
		}
	}
	if let Some(dkim) = &config.dkim {
		entries.push(format!("[dkim] key_file = {}", dkim.key_file.display()));
		if let Some(rsa) = &dkim.rsa_key_file {
			entries.push(format!("[dkim] rsa_key_file = {}", rsa.display()));
		}
	}
	if let Some(arc) = &config.arc {
		entries.push(format!("[arc] key_file = {}", arc.key_file.display()));
	}
	if let Some(storage) = &config.storage {
		if storage.encrypt_at_rest {
			if let Some(path) = &storage.encryption_key_file {
				encryption_key.push(format!(
					"[storage] encryption_key_file = {}",
					path.display()
				));
			}
			if let Some(var) = &storage.encryption_key_env {
				encryption_key.push(format!("[storage] encryption_key_env = ${var}"));
			}
			if encryption_key.is_empty() {
				encryption_key.push(
					"[storage] encrypt_at_rest = true (no encryption_key_file or encryption_key_env configured)"
						.to_string(),
				);
			}
		}
		if let Some(BlobBackendConfig::S3(s3)) = &storage.blobs {
			if let Some(path) = &s3.secret_access_key_file {
				entries.push(format!(
					"[storage.blobs] secret_access_key_file = {}",
					path.display()
				));
			}
			if let Some(var) = &s3.secret_access_key_env {
				entries.push(format!("[storage.blobs] secret_access_key_env = ${var}"));
			}
		}
	}
	if let Some(dns) = &config.dns {
		if let Some(path) = &dns.token_file {
			entries.push(format!("[dns] token_file = {}", path.display()));
		}
		if let Some(path) = &dns.credentials_file {
			entries.push(format!("[dns] credentials_file = {}", path.display()));
		}
	}

	if !entries.is_empty() {
		super::style::warn_to(
			warnings,
			format_args!(
				"this backup archives {archived} files under data_dir only. The configuration references the following paths outside data_dir that are NOT in this archive. Back them up separately or the corresponding capability will not work after a restore:"
			),
		);
		for entry in &entries {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}

	if !encryption_key.is_empty() {
		super::style::warn_to(
			warnings,
			"this backup carries the on-disk mail encrypted at rest. The [storage] encryption key is intentionally not in data_dir (storage-keygen: \"Store it off the data disk ... never written into data_dir\"). Without it the mail content in this archive is unrecoverable. Save the key separately:",
		);
		for entry in &encryption_key {
			let _ = writeln!(warnings, "  - {entry}");
		}
	}
}

/// Every regular file under `root`, as (archive-relative path, source mode, bytes).
///
/// The mode is read from the file's metadata so the archive round-trips the
/// permission bits the operator set, including the 0o600 they relied on for
/// DKIM/ACME/TLS private keys.
fn collect_files(root: &Path) -> std::io::Result<Vec<(String, u32, Vec<u8>)>> {
	let _warnings = crate::util::fs_walk::warning_scope();
	let mut out = Vec::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(dir) = stack.pop() {
		let entries = match crate::util::fs_walk::read_dir(&dir) {
			Ok(entries) => entries,
			// A missing data dir yields an empty backup, not an error.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(error),
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if entry.file_type()?.is_dir() {
				stack.push(path);
			} else if entry.file_type()?.is_file()
				&& let Ok(relative) = path.strip_prefix(root)
			{
				let name = format!("data/{}", relative.to_string_lossy());
				let metadata = entry.metadata()?;
				let mode = metadata.permissions().mode();
				out.push((name, mode, crate::util::fs_walk::read(&path)?));
			}
		}
	}
	out.sort_by(|a, b| a.0.cmp(&b.0));
	Ok(out)
}

/// Build the gzip-compressed archive; see [`tar_format`].
pub(in crate::cli) fn tar_gz(entries: &[(String, u32, Vec<u8>)]) -> std::io::Result<Vec<u8>> {
	tar_format::tar_gz(entries)
}

// The database dump/load code is split out into `db_dump` (the
// sibling module at the top of this file) so each compile unit
// stays under the per-file 500-line cap. Re-export the items the
// existing tests reach for so the test files' `use super::*;`
// glob keeps working unchanged.
#[allow(unused_imports)]
pub(crate) use db_dump::CapturedOutput;
#[allow(unused_imports)]
pub(super) use db_dump::collect_dump;
#[allow(unused_imports)]
pub(super) use db_dump::container_cp_into_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump_container;
#[allow(unused_imports)]
pub(super) use db_dump::pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::run_command_capturing_stdout;
// Test-only re-exports: the existing test files use `use super::*;`
// to reach `BackupError`, `CommandSpec`, and `split_url_password`.
// `pub(crate)` is the widest visibility a child of a non-public
// module can give; the test files are grandchildren of `crate::cli`
// and the re-export must reach them.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use db_dump::{BackupError, CommandSpec, split_url_password};

#[cfg(test)]
#[path = "helpers_tests.rs"]
mod helpers;

#[cfg(test)]
#[path = "../backup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../backup_restore_tests.rs"]
mod tests_b;

#[cfg(test)]
#[path = "../backup_pg_tests.rs"]
mod tests_pg;

#[cfg(test)]
#[path = "../backup_container_tests.rs"]
mod tests_container;

#[cfg(test)]
#[path = "../backup_restore_run_tests.rs"]
mod tests_restore_run;

#[cfg(test)]
#[path = "../backup_db_sql_tests.rs"]
mod tests_db_sql;

#[cfg(test)]
#[path = "../backup_restore_guards_tests.rs"]
mod tests_restore_guards;

#[cfg(test)]
#[path = "../backup_tests_paths.rs"]
mod tests_paths;

#[cfg(test)]
#[path = "../backup_tests_long_paths.rs"]
mod tests_long_paths;
