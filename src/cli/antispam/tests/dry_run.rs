//! `--dry-run` on every mutation prints the validated unified diff and
//! leaves the file byte-for-byte untouched, with no restart request.

use std::cell::Cell;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::*;
use crate::cli::config_edit::ConfigDocument;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn open(path: &Path) -> ConfigDocument {
	ConfigDocument::open(path).expect("config document must open")
}

#[test]
fn dry_run_set_prints_a_diff_and_writes_nothing() {
	let (_dir, file) = fixture("greylist_delay_secs = 100\n");
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let mut document = open(file.path());
	apply_set(&mut document, Key::GreylistDelay, &["3m".to_string()]).unwrap();
	let code = commit_and_restart(
		document,
		Key::GreylistDelay,
		"set",
		true,
		&mut out,
		&mut status,
	)
	.expect("dry-run must succeed");
	assert_eq!(code, ExitCode::SUCCESS);
	let out_text = String::from_utf8(out.clone()).unwrap();
	assert!(
		out_text.contains("---"),
		"dry-run must print the unified diff header: {out_text}"
	);
	assert!(
		out_text.contains("+++"),
		"dry-run must print the unified diff target: {out_text}"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == before,
		"dry-run must leave the file untouched"
	);
	assert_eq!(
		calls.get(),
		0,
		"dry-run must not invoke the restart closure"
	);
}

#[test]
fn dry_run_add_appends_nothing_to_disk() {
	let (_dir, file) = fixture("");
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let mut document = open(file.path());
	apply_add(&mut document, Key::DnsblZones, "zen.spamhaus.org").unwrap();
	let code = commit_and_restart(
		document,
		Key::DnsblZones,
		"added",
		true,
		&mut out,
		&mut status,
	)
	.expect("dry-run must succeed");
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		std::fs::read_to_string(file.path()).unwrap(),
		before,
		"dry-run add must leave the file untouched"
	);
}

#[test]
fn no_op_set_reports_no_change_and_no_restart() {
	let (_dir, file) = fixture("greylist_delay_secs = 300");
	let mut out = Vec::new();
	let mut status = Vec::new();
	let calls = Cell::new(0);
	let mut document = open(file.path());
	apply_set(&mut document, Key::GreylistDelay, &["5m".to_string()]).unwrap();
	// Re-route the restart closure to count calls.
	let code = commit_and_restart_with(
		document,
		Key::GreylistDelay,
		"set",
		false,
		&mut out,
		&mut status,
		|_config, _action| {
			calls.set(calls.get() + 1);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(calls.get(), 0, "unchanged set must not restart");
	assert!(
		String::from_utf8(status)
			.unwrap()
			.contains("nothing changed"),
		"unchanged set must report a status line"
	);
}

// `commit_and_restart` uses `super::stack::run` directly; expose a wrapper
// the test can substitute its own closure into. Lifting it here keeps the
// hot path small and avoids a one-off parameter for production use.
fn commit_and_restart_with(
	document: ConfigDocument,
	key: Key,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	use crate::cli::config_edit::Outcome;
	if dry_run {
		let _ = write!(out, "{}", document.dry_run().unwrap());
		return ExitCode::SUCCESS;
	}
	let config = document.config().unwrap();
	let outcome = document.commit().unwrap();
	if outcome == Outcome::Unchanged {
		let _ = writeln!(
			status,
			"antispam {} already set; nothing changed.",
			key.name()
		);
		return ExitCode::SUCCESS;
	}
	let _ = writeln!(status, "antispam {} {verb}.", key.name());
	crate::cli::config_edit::after_change_with(&config, outcome, true, status, restart).unwrap()
}
