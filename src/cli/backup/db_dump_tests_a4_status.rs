//! Tests for the exit status of the dump tool. A dump that printed the head
//! of the SQL and then failed is not a dump, so it must never reach the
//! archive: the operator would carry a truncated `database.sql` as a good
//! backup and only find out at restore time that rows are missing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;

use super::db_dump_marker::output_ends_with_pg_dump_complete;
use super::{BackupError, CommandSpec, Database, collect_dump_with, run_command_capturing_stdout};
use std::sync::mpsc;
use std::time::Duration;

/// Write an executable `/bin/sh` stub at `dest` that prints `body` on
/// stdout and exits with `exit_code`.
fn write_stub(dest: &Path, body: &str, exit_code: i32) {
	fs::write(
		dest,
		format!("#!/bin/sh\nprintf '%b' {body:?}\nexit {exit_code}\n"),
	)
	.expect("write stub");
	let mut perms = fs::metadata(dest).expect("stub stat").permissions();
	perms.set_mode(0o700);
	fs::set_permissions(dest, perms).expect("stub chmod");
}

/// A `Database` with a URL and no password file, so the host branch builds
/// a plain `pg_dump` invocation.
fn database() -> Database {
	toml::from_str(r#"url = "postgres://epistle@localhost/epistle""#).expect("database")
}

/// Lay down the compose layout so the container branch is selected, and
/// return the compose path.
fn place_compose(data_dir: &Path) {
	let compose_dir = data_dir.join("compose");
	fs::create_dir_all(&compose_dir).expect("compose dir");
	fs::write(compose_dir.join("compose.yaml"), "{}").expect("compose");
}

/// Run the dump against a stub named after the program it stands in for.
/// `compose` selects the container branch, `body` is what the stub prints on
/// stdout, and `exit_code` is what it reports.
fn dump_with_stub(
	stubs: &Path,
	program: &str,
	compose: bool,
	body: &'static str,
	exit_code: i32,
) -> Result<Vec<u8>, BackupError> {
	let data_dir = tempfile::tempdir().expect("data_dir");
	if compose {
		place_compose(data_dir.path());
	}
	let stub = stubs.join("dump-tool");
	write_stub(&stub, body, exit_code);
	crate::cli::backup::helpers::retry_on_text_file_busy(|| {
		let resolver = |candidate: &str| (candidate == program).then(|| stub.clone());
		collect_dump_with(&database(), data_dir.path(), &resolver)
	})
}

/// The host `pg_dump` exited non-zero after emitting SQL. The collect must
/// surface the failure rather than hand the partial bytes back as a dump.
#[test]
fn host_dump_that_failed_after_partial_output_is_refused() {
	let stubs = tempfile::tempdir().expect("stubs");
	let result = dump_with_stub(stubs.path(), "pg_dump", false, "-- partial schema\n", 23);
	match result {
		Err(BackupError::CommandFailed { code, .. }) => {
			assert_eq!(code, Some(23), "the dump tool's exit status must surface")
		}
		other => panic!("a failed dump must not be accepted, got {other:?}"),
	}
}

/// The same failure on the container branch, where the dump runs as
/// `podup exec`: the status has to be read there too.
#[test]
fn container_dump_that_failed_after_partial_output_is_refused() {
	let stubs = tempfile::tempdir().expect("stubs");
	let result = dump_with_stub(stubs.path(), "podup", true, "-- partial schema\n", 23);
	match result {
		Err(BackupError::CommandFailed { code, .. }) => {
			assert_eq!(code, Some(23), "the dump tool's exit status must surface")
		}
		other => panic!("a failed dump must not be accepted, got {other:?}"),
	}
}

/// A dump tool that failed without writing anything reports its failure,
/// not the empty-output symptom, so the operator reads the real cause.
#[test]
fn failed_dump_without_output_reports_the_failure() {
	let stubs = tempfile::tempdir().expect("stubs");
	let result = dump_with_stub(stubs.path(), "pg_dump", false, "", 7);
	match result {
		Err(BackupError::CommandFailed { code, .. }) => {
			assert_eq!(code, Some(7), "the dump tool's exit status must surface")
		}
		other => panic!("a failed dump must not be accepted, got {other:?}"),
	}
}

/// The other side of the floor: a dump that exited cleanly and ends with
/// pg_dump's closing marker is a dump, whatever its body wrote.
#[test]
fn clean_dump_is_accepted() {
	let stubs = tempfile::tempdir().expect("stubs");
	let result = dump_with_stub(
		stubs.path(),
		"pg_dump",
		false,
		"-- full schema\n-- PostgreSQL database dump complete\n",
		0,
	);
	match result {
		Ok(bytes) => assert_eq!(
			bytes,
			b"-- full schema\n-- PostgreSQL database dump complete\n"
		),
		Err(error) => panic!("a clean dump must not be refused, got {error:?}"),
	}
}

/// A clean exit with the tail missing the closing marker is a truncated
/// dump: the bytes look like a dump but the operator only finds out rows
/// are gone when restore time comes. The truncation can come from a
/// host-side truncation by `podman exec`, a `printf` end-of-stream, a
/// filesystem full mid-dump: anything that closes the pipe before pg_dump
/// prints its end marker. The marker gate is the only thing that catches
/// it.
#[test]
fn truncated_dump_with_clean_exit_is_refused() {
	let stubs = tempfile::tempdir().expect("stubs");
	let result = dump_with_stub(stubs.path(), "pg_dump", false, "-- partial schema\n", 0);
	match result {
		Err(BackupError::TruncatedDump) => {}
		other => panic!("a truncated dump must be refused as TruncatedDump, got {other:?}"),
	}
}

/// The archive is what the operator keeps. A dump that failed must leave
/// nothing in the stream the backup writes, so a truncated `database.sql`
/// can never reach the backups directory looking like a good archive.
#[test]
fn failed_dump_leaves_the_backup_stream_untouched() {
	let data_dir = tempfile::tempdir().expect("data_dir");
	let account = data_dir.path().join("accounts").join("alice").join("new");
	fs::create_dir_all(&account).expect("dirs");
	fs::write(account.join("m1.eml"), b"Subject: hi\r\n\r\nbody").expect("write");

	let stubs = tempfile::tempdir().expect("stubs");
	let stub = stubs.path().join("pg_dump");
	write_stub(&stub, "-- partial schema\n", 23);
	let resolver = move |program: &str| (program == "pg_dump").then(|| stub.clone());

	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 [database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.path().display()
	))
	.expect("config");

	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	let code = crate::cli::backup::run_with(&config, &mut archive, &mut warnings, &resolver);
	assert_eq!(code, ExitCode::FAILURE, "the backup must fail");
	assert!(
		archive.is_empty(),
		"a failed dump must not reach the archive stream ({} bytes)",
		archive.len()
	);
}

/// What pg_dump 18 prints at the end of a plain dump: the marker, a bare
/// comment line, a blank line and the `\unrestrict` line added in 2025.
const REAL_TAIL: &[u8] =
	b"CREATE TABLE t (id int);\n\n--\n-- PostgreSQL database dump complete\n--\n\n\\unrestrict kP3xQ9\n";

#[test]
fn closing_of_a_real_pg_dump_is_a_complete_dump() {
	assert!(output_ends_with_pg_dump_complete(REAL_TAIL));
	assert!(output_ends_with_pg_dump_complete(
		b"x\n--\n-- PostgreSQL database dump complete\n--\n\n"
	));
	assert!(output_ends_with_pg_dump_complete(
		b"x\n-- PostgreSQL database dump complete"
	));
}

#[test]
fn a_cut_dump_is_not_a_complete_dump() {
	assert!(!output_ends_with_pg_dump_complete(
		b"CREATE TABLE t (id int);\nCOPY t FROM stdin;\n1\n"
	));
	assert!(!output_ends_with_pg_dump_complete(b""));
	// The marker with more dump after it: a second dump glued on, or noise.
	assert!(!output_ends_with_pg_dump_complete(
		b"-- PostgreSQL database dump complete\nCOPY t FROM stdin;\n1\n"
	));
	// The marker inside another line is not the closing line.
	assert!(!output_ends_with_pg_dump_complete(
		b"INSERT INTO t VALUES ('-- PostgreSQL database dump complete');\n"
	));
}

/// The stub writes more than a pipe holds before it reads a byte, the way a
/// `psql` that prints as it replays a large dump does. A caller that finishes
/// writing the payload before it reads the output waits on the child while the
/// child waits on it.
#[test]
fn a_child_that_prints_before_it_reads_does_not_hang_on_a_large_payload() {
	let spec = CommandSpec::new(vec![
		"sh".to_string(),
		"-c".to_string(),
		"dd if=/dev/zero bs=1000 count=300 2>/dev/null; cat >/dev/null".to_string(),
	])
	.with_stdin(vec![b'x'; 4 * 1024 * 1024]);
	let (sender, receiver) = mpsc::channel();
	std::thread::spawn(move || {
		let _ = sender.send(run_command_capturing_stdout(&spec));
	});
	let output = receiver
		.recv_timeout(Duration::from_secs(30))
		.expect("the child must finish: the payload is written while the output is read")
		.expect("the child runs");
	assert!(output.status_ok, "the child exits cleanly");
	assert_eq!(output.stdout.len(), 300_000, "all of its output is kept");
}
