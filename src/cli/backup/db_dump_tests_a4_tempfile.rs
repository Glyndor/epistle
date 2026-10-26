//! Tests for the restore staging file. The SQL staged for a container
//! restore carries credential hashes, so the host copy must be `0600` from
//! the moment it is created and must not survive the restore, and the copy
//! inside the container must land on a name unique to that restore and be
//! removed from the container once the replay is over.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use libc;

use super::{
	BackupError, RestoreHostTemp, SQL_FILE_NAME, container_psql_load_spec, container_rm_temp_spec,
	load_dump_container_with,
};

/// Run the container restore against the `podup` stub at `stub`, giving the
/// kernel's occasional `ETXTBSY` on a just-written stub another try and
/// passing every other outcome back untouched.
fn restore_against_stub(compose: &Path, stub: &Path) -> Result<(), BackupError> {
	let resolver = move |program: &str| (program == "podup").then(|| stub.to_path_buf());
	crate::cli::backup::helpers::retry_on_text_file_busy(|| {
		load_dump_container_with(compose, b"select 1;\n", &resolver)
	})
}

/// Pin the process umask for the lifetime of the guard. `umask(2)` has no
/// per-thread form, so the guard covers only the call that creates files,
/// not the assertions that read them back.
pub(super) struct UmaskGuard {
	previous: libc::mode_t,
}

impl UmaskGuard {
	pub(super) fn new(value: libc::mode_t) -> Self {
		// SAFETY: `umask` takes and returns a `mode_t` and touches no memory
		// the caller owns, so the call is sound from safe code.
		let previous = unsafe { libc::umask(value) };
		Self { previous }
	}
}

impl Drop for UmaskGuard {
	fn drop(&mut self) {
		// SAFETY: same as the constructor; restores what the process
		// started with.
		unsafe {
			libc::umask(self.previous);
		}
	}
}

/// Lay down the compose layout `compose_file_path(data_dir)` expects, so the
/// restore takes the container branch.
fn place_compose(data_dir: &Path) -> PathBuf {
	let compose_dir = data_dir.join("compose");
	fs::create_dir_all(&compose_dir).expect("compose dir");
	let compose = compose_dir.join("compose.yaml");
	fs::write(&compose, "{}").expect("compose");
	compose
}

/// Write an executable `/bin/sh` stub at `dest`. `body` may reference `$@`,
/// which lets a caller record the argv it was handed. The bytes go to a
/// side name first and are renamed into place, so the path the test execs
/// never exists in a half-written state.
fn write_stub(dest: &Path, body: &str) {
	let staged = dest.with_extension("staged");
	fs::write(&staged, format!("#!/bin/sh\n{body}\n")).expect("write stub");
	let mut perms = fs::metadata(&staged).expect("stub stat").permissions();
	perms.set_mode(0o700);
	fs::set_permissions(&staged, perms).expect("stub chmod");
	fs::rename(&staged, dest).expect("publish stub");
}

/// The permission bits of `path`, masked to the nine that matter.
fn mode_of(path: &Path) -> u32 {
	fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

/// Under the permissive umask a plain create would land at `0644`. The
/// staged SQL must be `0600` from creation, before anyone has a chance to
/// read it.
#[test]
fn host_restore_temp_is_0600_under_umask_022() {
	let mask = UmaskGuard::new(0o022);
	let mut temp = RestoreHostTemp::create().expect("restore temp");
	temp.write_all(b"-- credential hash\n").expect("write");
	let mode = mode_of(temp.path());
	let dir_mode = mode_of(temp.dir());
	drop(mask);
	assert_eq!(
		mode, 0o600,
		"host restore temp landed at {mode:o}, must be 0600"
	);
	assert_eq!(
		dir_mode, 0o700,
		"the directory holding it landed at {dir_mode:o}, must be 0700"
	);
}

/// The guard owns the removal, so an abandoned temp cannot survive the
/// restore that made it.
#[test]
fn drop_guard_removes_the_host_temp() {
	let mut temp = RestoreHostTemp::create().expect("restore temp");
	temp.write_all(b"x").expect("write");
	let path = temp.path().to_path_buf();
	let dir = temp.dir().to_path_buf();
	assert!(
		path.exists(),
		"the staged file exists while the guard holds it"
	);
	drop(temp);
	assert!(!path.exists(), "the staged file must not survive its guard");
	assert!(!dir.exists(), "nor its directory");
}

/// Drive the container restore against a `podup` stub that appends its argv
/// to `record` and exits non-zero on the copy step. Returns the
/// argv lines the stub recorded.
fn run_failing_container_restore(stubs: &Path) -> Vec<String> {
	let record = stubs.join("argv.log");
	let stub = stubs.join("podup-fail");
	// `$0` joins into `$*` so the recorded line starts with the program
	// name (`podup`) and a test can find the call by argv position.
	write_stub(
		&stub,
		&format!(
			"printf '%s\\n' \"$0 $*\" >> '{}'\ncase \"$*\" in *' cp '*) exit 5;; esac\nexit 0",
			record.display()
		),
	);

	let data_dir = tempfile::tempdir().expect("data_dir");
	let compose = place_compose(data_dir.path());
	let result = restore_against_stub(&compose, &stub);
	assert!(result.is_err(), "the failing stub must fail the restore");

	fs::read_to_string(&record)
		.expect("argv log")
		.lines()
		.map(str::to_string)
		.collect()
}

/// The staged host file must be gone once the restore returns, error path
/// included. Without the guard the bytes sit under the system temp
/// directory until something else cleans it up, long after the restore
/// gave up.
#[test]
fn failed_restore_removes_the_host_temp() {
	let stubs = tempfile::tempdir().expect("stubs");
	let calls = run_failing_container_restore(stubs.path());
	let cp_call = cp_call_words(&calls);
	let host_path = cp_call
		.iter()
		.skip_while(|arg| **arg != "cp")
		.nth(1)
		.expect("the cp step named the staged file");
	assert!(
		!Path::new(host_path).exists() && !Path::new(host_path).parent().unwrap().exists(),
		"the staged SQL survived a failed restore: {host_path}"
	);
}

/// Two restores overlapping in time must not write over each other inside
/// the container, so the staged name has to be unique while the previous
/// one is still on disk. The clock alone is not enough: two restores in the
/// same process can land on the same reading, so the exclusive create has to
/// move to the next candidate.
#[test]
fn overlapping_staging_files_do_not_share_a_name() {
	let first = RestoreHostTemp::create().expect("first temp");
	let second = RestoreHostTemp::create().expect("second temp");
	assert_ne!(
		first.path(),
		second.path(),
		"two live staged files must not collide"
	);
	assert!(first.path().exists() && second.path().exists());
}

/// The copy inside the container goes into a directory named after the
/// staged host directory, so it carries that name's uniqueness, and it is
/// never the fixed name two restores would fight over.
#[test]
fn container_copy_is_named_after_the_staged_directory() {
	let stubs = tempfile::tempdir().expect("stubs");
	let calls = run_failing_container_restore(stubs.path());
	let cp_call = cp_call_words(&calls);
	let host_path = cp_call
		.iter()
		.skip_while(|arg| **arg != "cp")
		.nth(1)
		.expect("the cp step named the staged file");
	let destination = cp_call.last().expect("the cp step named a destination");
	let staged_dir = Path::new(host_path)
		.parent()
		.and_then(Path::file_name)
		.map(|name| name.to_string_lossy().into_owned())
		.expect("the staged path has a directory");
	assert_eq!(
		destination,
		&format!("db:/tmp/{staged_dir}/{SQL_FILE_NAME}"),
		"the container copy must reuse the unique staged name"
	);
	assert!(
		!destination.contains("/tmp/epistle-restore.sql"),
		"the container copy must not use a fixed name (got {destination})"
	);
}

/// The replay shell execs `psql`, not the wrapper. The shell that runs
/// the cmdline is replaced by `psql` so a SIGTERM sent to the
/// `podup exec` (an operator hitting Ctrl-C, a timeout firing, the
/// runner aborting the call) reaches `psql` and aborts the transaction,
/// not the empty shell that has nothing left to do. The drop-the-temp
/// step has to move to the host side because the wrapper shell is gone.
#[test]
fn container_replay_script_uses_exec_psql() {
	let data_dir = tempfile::tempdir().expect("data_dir");
	let compose = place_compose(data_dir.path());
	let in_container_path = "/tmp/epistle-restore-1234-999/restore.sql";
	let spec = container_psql_load_spec(&compose, in_container_path, b"select 1;\n").expect("spec");
	let script = spec.argv().last().expect("last argv");
	assert!(
		script.contains(" exec psql "),
		"the replay shell must exec psql so SIGTERM reaches psql, got: {script}"
	);
	assert!(
		!script.contains("trap "),
		"no trap can survive `exec psql`; got: {script}"
	);
	assert!(
		!script.contains("rm -"),
		"the in-container removal has moved to the host; got: {script}"
	);
}

/// The replay shell must not try to change the owner or the mode of the
/// copy: `podup cp` leaves it owned by the host user on some engines, and the
/// container user cannot `chmod` a file it does not own. That was the
/// `Operation not permitted` that stopped every restore. The directory the
/// copy sits in is what keeps others out.
#[test]
fn container_replay_script_does_not_change_the_copy() {
	let data_dir = tempfile::tempdir().expect("data_dir");
	let compose = place_compose(data_dir.path());
	let path = "/tmp/epistle-restore-1234-999/restore.sql";
	let spec = container_psql_load_spec(&compose, path, b"select 1;\n").expect("spec");
	let script = spec.argv().last().expect("last argv");
	assert!(
		!script.contains("chmod") && !script.contains("chown"),
		"the replay must not touch the copy's owner or mode, got: {script}"
	);
}

/// The host-side cleanup spec is `podup exec -T -u root db sh -c "rm -rf <dir>"`,
/// the last podup call in the restore flow (after mkdir, cp and psql).
#[test]
fn host_rm_temp_spec_targets_db_service_with_no_tty() {
	let data_dir = tempfile::tempdir().expect("data_dir");
	let compose = place_compose(data_dir.path());
	let spec = container_rm_temp_spec(&compose, "/tmp/epistle-restore-1234-999").expect("spec");
	let argv = spec.argv();
	assert_eq!(argv[0], "podup");
	assert_eq!(argv[3], "exec");
	assert_eq!(argv[4], "-T");
	assert!(
		argv[5..]
			== [
				"-u",
				"root",
				"db",
				"sh",
				"-c",
				"rm -rf '/tmp/epistle-restore-1234-999'"
			],
		"the host-side cleanup must run rm -rf inside db as the owner of the directory; got: {argv:?}"
	);
}

/// Drive the container restore against a stub `podup` that succeeds on
/// every call, and returns the recorded argv lines (one per invocation)
/// so a test can assert the cleanup was issued after a successful replay.
fn run_successful_container_restore(stubs: &Path) -> Vec<String> {
	let record = stubs.join("argv.log");
	let stub = stubs.join("podup-ok");
	// Always exit 0, regardless of which podup subcommand was issued.
	write_stub(
		&stub,
		&format!("printf '%s\\n' \"$0 $*\" >> '{}'\nexit 0", record.display()),
	);

	let data_dir = tempfile::tempdir().expect("data_dir");
	let compose = place_compose(data_dir.path());
	let result = restore_against_stub(&compose, &stub);
	assert!(
		result.is_ok(),
		"the OK stub must succeed the restore: {result:?}"
	);

	fs::read_to_string(&record)
		.expect("argv log")
		.lines()
		.map(str::to_string)
		.collect()
}

/// Returns the argv line that contained `subcommand`. Each line is the
/// argv of one podup invocation, flattened by the recording stub.
fn find_call<'a>(calls: &'a [String], subcommand: &str) -> &'a str {
	calls
		.iter()
		.find(|line| line.contains(subcommand))
		.unwrap_or_else(|| panic!("no recorded argv contained {subcommand:?}: {calls:?}"))
		.as_str()
}

/// The argv words of the copy step. The call is found by its subcommand
/// rather than by position: a restore that had to retry a refused spawn
/// records the cleanup of the abandoned attempt before the copy that counts.
fn cp_call_words(calls: &[String]) -> Vec<&str> {
	find_call(calls, " cp ")
		.split_whitespace()
		.collect::<Vec<_>>()
}

/// A successful replay still issues the host-side `podup exec -T db rm -rf`,
/// so the SQL bytes do not linger inside the container after a clean restore.
/// Without it a follow-up restore could read the prior file if `podup cp`
/// allowed the destination to be reused, and the file would survive the
/// container until something else cleaned `/tmp` up.
#[test]
fn successful_restore_removes_the_in_container_temp_from_the_host() {
	let stubs = tempfile::tempdir().expect("stubs");
	let calls = run_successful_container_restore(stubs.path());
	let rm_call = find_call(&calls, "rm -rf");
	assert!(
		rm_call.contains(" exec -T -u root db sh -c "),
		"the cleanup must exec inside the db service with no TTY; got: {rm_call}"
	);
	let script_start = rm_call.find("rm -rf").expect("rm -rf in the cleanup call");
	assert!(
		rm_call[script_start..].contains("'/tmp/"),
		"the cleanup script must rm a path inside the container /tmp; got: {rm_call}"
	);
}

/// A failed replay (the cp step or the psql step errors out) must still
/// trigger the host-side cleanup. The wrapper shell that drops the temp is
/// gone (it has been replaced by `exec psql` so SIGTERM reaches psql), so
/// the only path to remove the in-container file is the `podup exec rm -f`
/// the host fires unconditionally.
#[test]
fn failed_restore_removes_the_in_container_temp_from_the_host() {
	let stubs = tempfile::tempdir().expect("stubs");
	let calls = run_failing_container_restore(stubs.path());
	let rm_call = find_call(&calls, "rm -rf");
	assert!(
		rm_call.contains(" exec -T -u root db sh -c "),
		"the cleanup must exec inside the db service with no TTY on error; got: {rm_call}"
	);
	let script_start = rm_call.find("rm -rf").expect("rm -rf in the cleanup call");
	assert!(
		rm_call[script_start..].contains("'/tmp/"),
		"the cleanup script must rm a path inside the container /tmp on error; got: {rm_call}"
	);
}
