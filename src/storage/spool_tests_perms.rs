//! Spool filesystem permissions and migration of loose files at open time.
//!
//! Every spool file is created with mode 0600 and every spool directory with
//! 0700, regardless of the umask. A file already on disk with looser
//! permissions is retightened on open, and the count is logged once.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::FsSpool;

fn mode(path: &Path) -> u32 {
	std::fs::metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

fn chmod(path: &Path, mode: u32) {
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn chmod_dir(path: &Path, mode: u32) {
	chmod(path, mode);
	if let Ok(rd) = std::fs::read_dir(path) {
		for entry in rd.flatten() {
			chmod(&entry.path(), mode);
		}
	}
}

/// A freshly written spool entry's files and directories are 0600/0700 even
/// when nothing else is changing the umask for the process.
#[test]
fn spool_files_are_owner_only_on_a_permissive_process() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Force every newly created file or directory to come out world-writable.
	// The libc umask is process-wide, so guard the test with the lockfile
	// pattern this codebase already uses elsewhere.
	#[allow(unsafe_code)]
	unsafe {
		libc::umask(0o000);
	}
	let spool = FsSpool::open(dir.path()).expect("open");
	let id = spool
		.store(&sample_message_owned(), None, &Default::default())
		.expect("store");

	let root = dir.path().join("spool");
	let new_dir = root.join("new");
	let tmp_dir = root.join("tmp");
	let envelope = new_dir.join(format!("{id}.json"));
	let body = new_dir.join(format!("{id}.eml"));

	assert_eq!(mode(&root), 0o700, "spool root must be 0700");
	assert_eq!(mode(&new_dir), 0o700, "spool new/ must be 0700");
	assert_eq!(mode(&tmp_dir), 0o700, "spool tmp/ must be 0700");
	assert_eq!(mode(&envelope), 0o600, "envelope must be 0600");
	assert_eq!(mode(&body), 0o600, "body must be 0600");
}

/// Legacy files left on disk with looser permissions are retightened by
/// the audit the server runs at start-up, and the audit is idempotent.
#[test]
fn open_retightens_loose_files_and_logs_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool_root = dir.path().join("spool");
	let new_dir = spool_root.join("new");
	let tmp_dir = spool_root.join("tmp");
	std::fs::create_dir_all(&new_dir).expect("new");
	std::fs::create_dir_all(&tmp_dir).expect("tmp");
	chmod_dir(&spool_root, 0o755);
	chmod_dir(&new_dir, 0o755);
	chmod_dir(&tmp_dir, 0o755);

	let envelope = new_dir.join("01939b5e-7c00-7ccc-aaaa-000000000001.json");
	let body = new_dir.join("01939b5e-7c00-7ccc-aaaa-000000000001.eml");
	std::fs::write(&envelope, b"{}").expect("envelope");
	std::fs::write(&body, b"plain").expect("body");
	chmod(&envelope, 0o644);
	chmod(&body, 0o644);

	// The audit is what retightens; opening the spool alone is now
	// side-effect-free on permissions, so the operator command that just
	// observes (the `spool` status check) sees the current state instead
	// of silently fixing it.
	let spool = FsSpool::open(dir.path()).expect("open");
	let fixed = spool.audit_permissions().expect("audit");
	assert_eq!(fixed, 2, "two loose files must be retightened");
	assert_eq!(mode(&spool_root), 0o700, "spool root retightened");
	assert_eq!(mode(&new_dir), 0o700, "new/ retightened");
	assert_eq!(mode(&tmp_dir), 0o700, "tmp/ retightened");
	assert_eq!(mode(&envelope), 0o600, "envelope retightened");
	assert_eq!(mode(&body), 0o600, "body retightened");

	// Re-running the audit after the first open reports zero fixes.
	let fixed_again = spool.audit_permissions().expect("audit");
	assert_eq!(fixed_again, 0, "audit must be idempotent");
}

/// Even on a confined umask that strips everything, the spool keeps files
/// owner-readable, so the server itself can read them back after a reload.
#[test]
fn spool_files_stay_readable_under_a_restrictive_umask() {
	let dir = tempfile::tempdir().expect("tempdir");
	#[allow(unsafe_code)]
	unsafe {
		libc::umask(0o077);
	}
	let spool = FsSpool::open(dir.path()).expect("open");
	let id = spool
		.store(&sample_message_owned(), None, &Default::default())
		.expect("store");
	let entry = spool.load(id).expect("load");
	assert_eq!(entry.data, sample_message_owned().data);

	let new_dir = dir.path().join("spool/new");
	let envelope = new_dir.join(format!("{id}.json"));
	assert_eq!(mode(&envelope), 0o600);
}

/// A staging file under `tmp/` created by an `update_envelope` is also
/// created with the explicit mode, not whatever the umask happens to be.
#[test]
fn update_envelope_writes_owner_only_staging_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	#[allow(unsafe_code)]
	unsafe {
		libc::umask(0o000);
	}
	let spool = FsSpool::open(dir.path()).expect("open");
	let id = spool
		.store(&sample_message_owned(), None, &Default::default())
		.expect("store");

	spool
		.update_envelope(id, |envelope| envelope.attempts += 1)
		.expect("update");

	let envelope = dir.path().join("spool/new").join(format!("{id}.json"));
	assert_eq!(mode(&envelope), 0o600);
}

fn sample_message_owned() -> crate::smtp::session::AcceptedMessage {
	use crate::smtp::session::AcceptedMessage;
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}
