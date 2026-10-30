//! Spool filesystem permissions and migration of loose files at open time.
//!
//! Every spool file is created with mode 0600 and every spool directory with
//! 0700, regardless of the umask. A file already on disk with looser
//! permissions is retightened by the start-up audit.
//!
//! The tests never change the umask: it is process-wide, and the lib suite
//! runs thousands of tests in parallel that create files. Under the usual
//! 022 or 002 umask a create without an explicit mode yields 0644/0664 and
//! 0755/0775, which the exact-mode assertions below reject.

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

/// A freshly written spool entry's files and directories are exactly
/// 0600/0700, not whatever the umask leaves.
#[test]
fn spool_files_are_owner_only_on_a_permissive_process() {
	let dir = tempfile::tempdir().expect("tempdir");
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

/// The pinned mode keeps files owner-readable, so the server itself reads
/// them back after a reload.
#[test]
fn spool_files_stay_readable_by_the_owner() {
	let dir = tempfile::tempdir().expect("tempdir");
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

/// A link planted in the spool never steers the start-up audit, which can
/// run as root before privileges drop, or the status count onto a file or a
/// directory outside the spool.
#[test]
fn audit_and_count_never_follow_a_link_out_of_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let victim_dir = outside.path().join("etc");
	std::fs::create_dir(&victim_dir).expect("victim dir");
	let victim_inner = victim_dir.join("inner.eml");
	std::fs::write(&victim_inner, b"x").expect("victim inner");
	let victim_file = outside.path().join("victim.json");
	std::fs::write(&victim_file, b"{}").expect("victim file");
	chmod(&victim_dir, 0o755);
	chmod(&victim_inner, 0o644);
	chmod(&victim_file, 0o644);

	let spool = FsSpool::open(dir.path()).expect("open");
	let new_dir = dir.path().join("spool/new");
	std::os::unix::fs::symlink(&victim_dir, new_dir.join("linked")).expect("dir link");
	std::os::unix::fs::symlink(
		&victim_file,
		new_dir.join("01939b5e-7c00-7ccc-aaaa-000000000002.json"),
	)
	.expect("file link");

	let loose = spool.count_loose_permissions().expect("count");
	let fixed = spool.audit_permissions().expect("audit");
	assert_eq!(
		mode(&victim_file),
		0o644,
		"a linked file outside keeps its mode"
	);
	assert_eq!(
		mode(&victim_inner),
		0o644,
		"a file under a linked dir keeps its mode"
	);
	assert_eq!(
		mode(&victim_dir),
		0o755,
		"a linked directory keeps its mode"
	);
	assert_eq!(
		(loose, fixed),
		(0, 0),
		"nothing outside the spool is counted"
	);
}

/// The retighten step never follows a link: an entry swapped for a link
/// between the listing and the change cannot redirect the change onto the
/// link's target.
#[test]
fn retighten_never_follows_a_link_swapped_in_after_the_listing() {
	use std::os::unix::fs::MetadataExt;

	use super::permissions::{Kind, retighten};

	let dir = tempfile::tempdir().expect("tempdir");
	let victim = dir.path().join("victim.json");
	std::fs::write(&victim, b"{}").expect("victim");
	chmod(&victim, 0o644);
	let swapped = dir.path().join("01939b5e-7c00-7ccc-aaaa-000000000003.json");
	std::os::unix::fs::symlink(&victim, &swapped).expect("link");
	let owner = std::fs::metadata(dir.path()).expect("owner").uid();

	let changed = retighten(&swapped, Kind::File, owner, true).expect("retighten");
	assert_eq!(mode(&victim), 0o644, "the link target must keep its mode");
	assert!(!changed, "a link is never counted as loose");
}

/// The start-up open never carries on with a spool it could not make
/// owner-only. A loose file the server cannot open (owner write-only, group
/// and world readable) is either retightened (as root) or the open fails;
/// it is never left loose behind a successful start.
#[test]
fn start_up_refuses_a_spool_it_cannot_tighten() {
	let dir = tempfile::tempdir().expect("tempdir");
	FsSpool::open(dir.path()).expect("lay out");
	let stuck = dir
		.path()
		.join("spool/new/01939b5e-7c00-7ccc-aaaa-000000000004.json");
	std::fs::write(&stuck, b"{}").expect("stuck");
	chmod(&stuck, 0o244);

	let opened =
		FsSpool::open_audited(dir.path(), crate::storage::MessageCrypto::disabled()).is_ok();
	assert!(
		!opened || mode(&stuck) == 0o600,
		"a start-up that succeeds must leave no loose spool file"
	);
}
