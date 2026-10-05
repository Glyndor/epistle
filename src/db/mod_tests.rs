//! Tests for the PostgreSQL version floor and the pure function that enforces
//! it.

use super::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

/// The variant name of a `DbError`, for the assertion messages that
/// must not print the full Debug. The `PasswordFile` variant carries a
/// path and a `PasswordFileError`, neither of which is a credential
/// itself, but the panic message has to be a CI log; printing the
/// full Debug would make the line wider and noisier than the
/// diagnosis needs. The match is exhaustive on purpose: a new
/// variant added to `DbError` breaks this file at compile time, so
/// the next caller cannot fall through and print the whole struct.
fn error_name(error: &DbError) -> &'static str {
	match error {
		DbError::Connect(_) => "Connect",
		DbError::Migrate(_) => "Migrate",
		DbError::InvalidUrl(_) => "InvalidUrl",
		DbError::ServerTooOld { .. } => "ServerTooOld",
		DbError::BadServerVersion(_) => "BadServerVersion",
		DbError::PasswordFile { .. } => "PasswordFile",
	}
}

/// "Ok(<N>)" or "<error variant>", for the `Ok(N)` fall-through cases
/// of the floor tests: the result carries the decoded major in the
/// `Ok` arm, the error variant in the `Err` arm. The match is
/// exhaustive on purpose for the same reason `error_name` is.
fn result_name(result: &Result<u32, DbError>) -> String {
	match result {
		Ok(major) => format!("Ok({major})"),
		Err(error) => error_name(error).to_string(),
	}
}

/// A `server_version_num` at the floor decodes to the floor and passes.
#[test]
fn major_at_the_floor_passes() {
	match major_meets_floor(140_012, MIN_SERVER_VERSION) {
		Ok(14) => {}
		other => panic!("expected Ok(14), got {}", result_name(&other)),
	}
}

/// A `server_version_num` above the floor decodes to its own major and
/// passes.
#[test]
fn major_above_the_floor_passes() {
	match major_meets_floor(180_001, MIN_SERVER_VERSION) {
		Ok(18) => {}
		other => panic!("expected Ok(18), got {}", result_name(&other)),
	}
}

/// A `server_version_num` below the floor is refused with the exact
/// `found` and `required` pair the operator will read in the startup error.
#[test]
fn major_below_the_floor_is_refused() {
	match major_meets_floor(130_015, MIN_SERVER_VERSION) {
		Err(DbError::ServerTooOld {
			found: 13,
			required: 14,
		}) => {}
		other => panic!(
			"expected ServerTooOld {{ found: 13, required: 14 }}, got {}",
			result_name(&other)
		),
	}
}

/// The CI matrix in `.github/workflows/db.yml` must include a
/// `postgres:<N>@sha256:...` image entry where `<N>` is
/// [`MIN_SERVER_VERSION`]. Reading the workflow from disk makes the
/// floor and the CI leg the same fact in two places: a change to one
/// that the other does not track is caught here, not by a post-mortem
/// against the wrong server.
///
/// The needle is `postgres:<N>@sha256:` (with the digest delimiter) so
/// the test cannot false-positive on a comment that just names the
/// major: the only place the image line appears is the matrix.
#[test]
fn the_floor_constant_is_the_one_ci_tests() {
	let workflow =
		fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/db.yml"))
			.expect("read .github/workflows/db.yml");
	let needle = format!("postgres:{MIN_SERVER_VERSION}@sha256:");
	assert!(
		workflow.contains(&needle),
		".github/workflows/db.yml must carry {needle:?} in its matrix so the \
		 floor declared in code and the floor tested in CI cannot drift apart; \
		 the workflow was: {workflow}"
	);
}

/// `read_password_file` strips exactly one trailing line ending and no
/// more. The four cases below pin the contract: a Unix-style trailing
/// `\n` goes; a Windows-style trailing `\r\n` goes (the `\r` is part
/// of the line ending, not part of the secret); a bare trailing `\r`
/// stays (a secret can legitimately end in `\r`, and a stray `\r` is
/// not a line ending on its own); a doubled `\n\n` keeps the inner
/// `\n` because only one line ending is stripped. The tests are
/// deliberately byte-exact: writing a `String` through `fs::write`
/// would let a future UTF-8 boundary mangle the `\r` case on a writer
/// that re-encodes, so the helper writes the raw bytes.
#[test]
fn password_file_strips_one_line_ending() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw");
	assert_eq!(
		read_password_file(&write_bytes(&path, b"pw\n")).expect("pw\\n"),
		"pw",
		"`\\n` is one line ending and must be stripped"
	);
	assert_eq!(
		read_password_file(&write_bytes(&path, b"pw\r\n")).expect("pw\\r\\n"),
		"pw",
		"`\\r\\n` is one line ending and must be stripped"
	);
	assert_eq!(
		read_password_file(&write_bytes(&path, b"pw\r")).expect("pw\\r"),
		"pw\r",
		"a bare `\\r` is not a line ending; the password keeps it"
	);
	assert_eq!(
		read_password_file(&write_bytes(&path, b"pw\n\n")).expect("pw\\n\\n"),
		"pw\n",
		"only one line ending is stripped; an inner `\\n` stays"
	);
}

/// Write `bytes` to `path` and chmod the result to `0600` so the file
/// passes `open_password_file`'s mode check (the bit rule the operator
/// deploys under; tests must mirror it). The `tempfile` guard lives
/// for the duration of the test, and the OS reclaims the directory when
/// the test ends. `fs::write` would also work, but routing through
/// `write_all` keeps the call site focused on the byte sequence the
/// test cares about.
fn write_bytes(path: &Path, bytes: &[u8]) -> std::path::PathBuf {
	use std::io::Write as _;
	use std::os::unix::fs::PermissionsExt as _;
	let mut file = fs::File::create(path).expect("create password file");
	file.write_all(bytes).expect("write password file");
	fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
	path.to_path_buf()
}

/// `read_password_file` refuses a file that contains only a line
/// ending (an empty secret after the strip) and surfaces it as
/// [`DbError::PasswordFile`] with the [`PasswordFileError::Empty`]
/// variant. The test guards the operator-facing message: a
/// mounted-but-empty secret must not silently match an unset
/// `PGPASSWORD` or `~/.pgpassfile` row.
#[test]
fn password_file_refuses_an_empty_secret_after_stripping() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw");
	match read_password_file(&write_bytes(&path, b"\n")).expect_err("\\n alone must error") {
		DbError::PasswordFile {
			kind: PasswordFileError::Empty,
			..
		} => {}
		other => panic!("expected PasswordFile {{ Empty, .. }}, got {}", error_name(&other)),
	}
}

/// `read_password_file` reads a `0600` file from the open descriptor
/// and returns the trimmed secret. Pins the happy path: a regular file
/// in the mode range the validator accepts is read and stripped. The
/// earlier `password_file_strips_one_line_ending` covers the
/// line-ending rules; this case only confirms the open + read chain
/// works end-to-end on a clean input.
#[cfg(unix)]
#[test]
fn password_file_reads_a_0600_file() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw_0600");
	assert_eq!(
		read_password_file(&write_bytes(&path, b"correct horse battery staple\n"))
			.expect("0600 reads"),
		"correct horse battery staple",
		"a 0600 file with a trailing newline is read and trimmed"
	);
}

/// A file with `mode & 0o077 != 0` is refused by the same bit rule
/// the config file is checked against. The refusal carries the
/// observed mode so the operator can see which bit needs clearing.
/// Without the open-descriptor check, validation and connect would
/// have separate code paths and a window where the file mode could
/// change between them; with the check on the open `File`, the
/// validator and the pool constructor agree.
#[cfg(unix)]
#[test]
fn password_file_refuses_a_group_readable_file() {
	use std::os::unix::fs::PermissionsExt as _;
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw_0644");
	write_bytes(&path, b"pw\n");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
	match read_password_file(&path).expect_err("0644 must be refused") {
		DbError::PasswordFile {
			kind: PasswordFileError::InsecureMode { mode },
			..
		} => assert_eq!(
			mode, 0o644,
			"the observed mode must round-trip through the variant"
		),
		other => panic!("expected InsecureMode {{ mode: 0o644, .. }}, got {}", error_name(&other)),
	}
}

/// A symlink at the path is refused. `open_password_file` opens with
/// `O_NOFOLLOW`; the kernel returns `ELOOP` and the variant surfaces
/// as `PasswordFileError::Io` carrying the underlying error. The
/// `raw_os_error` assertion pins the kernel-level reason so a future
/// refactor that loses `O_NOFOLLOW` (and falls through to following
/// the symlink) fails this test.
#[cfg(unix)]
#[test]
fn password_file_refuses_a_symlink() {
	let dir = tempdir().expect("tempdir");
	let target = dir.path().join("pw_target");
	write_bytes(&target, b"pw\n");
	let link = dir.path().join("pw_link");
	std::os::unix::fs::symlink(&target, &link).expect("symlink");
	match read_password_file(&link).expect_err("symlink must be refused") {
		DbError::PasswordFile {
			kind: PasswordFileError::Io(source),
			..
		} => assert_eq!(
			source.raw_os_error(),
			Some(libc::ELOOP),
			"O_NOFOLLOW on a symlink returns ELOOP, got {source:?}"
		),
		other => panic!("expected PasswordFile {{ Io(ELOOP), .. }}, got {}", error_name(&other)),
	}
}

/// A FIFO at the path is refused without blocking. `open_password_file`
/// opens with `O_NONBLOCK` so a FIFO with no writer cannot make the
/// pool constructor hang on a never-arriving writer. The test holds no
/// write descriptor for the FIFO; without `O_NONBLOCK` the read open
/// would block forever and the test would hang. With `O_NONBLOCK` the
/// open returns promptly; on kernels that report `ENXIO` for a
/// reader-less FIFO the function surfaces it as `Io(ENXIO)`, on
/// kernels that complete the open regardless the subsequent `fstat`
/// sees `S_IFIFO` and returns `NotRegularFile`. Either refusal is
/// correct: the function must not block, and the variant is whatever
/// the kernel handed back. The test asserts the refusal and the
/// function returns within finite time (the absence of a hang is the
/// proof that `O_NONBLOCK` is in effect).
#[cfg(unix)]
#[test]
fn password_file_refuses_a_fifo_without_blocking() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw_fifo");
	let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("nul-free path");
	// SAFETY: `c_path` is a NUL-terminated C string valid for the
	// duration of the call; the mode is the conventional `0o600`
	// (the test does not depend on the bit pattern; only on the entry
	// being a FIFO).
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
	match read_password_file(&path).expect_err("FIFO must be refused") {
		DbError::PasswordFile {
			kind: PasswordFileError::NotRegularFile,
			..
		} => {}
		DbError::PasswordFile {
			kind: PasswordFileError::Io(_),
			..
		} => {}
		other => panic!("expected PasswordFile with NotRegularFile or Io, got {}", error_name(&other)),
	}
}

/// A FIFO at the path is also refused when a writer is present, so
/// the fstat check is independent of the open behavior. The test
/// holds the FIFO open for read and write (`O_RDWR` on a FIFO never
/// blocks, even on the writer side); the read open in
/// `open_password_file` succeeds, the subsequent `fstat` sees
/// `S_IFIFO`, and the function returns `NotRegularFile`. This pins the
/// fstat branch: even when the open succeeds, a non-regular file is
/// refused.
#[cfg(unix)]
#[test]
fn password_file_refuses_a_fifo_with_a_writer() {
	let dir = tempdir().expect("tempdir");
	let path = dir.path().join("pw_fifo_w");
	let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("nul-free path");
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
	// `O_RDWR` on a FIFO never blocks: the same process holds both
	// ends, so the kernel sees a writer is present and the read open
	// in `open_password_file` returns immediately.
	let _holder = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.open(&path)
		.expect("open fifo rdwr");
	match read_password_file(&path).expect_err("FIFO with a writer must be refused") {
		DbError::PasswordFile {
			kind: PasswordFileError::NotRegularFile,
			..
		} => {}
		other => panic!("expected PasswordFile {{ NotRegularFile, .. }}, got {}", error_name(&other)),
	}
}
