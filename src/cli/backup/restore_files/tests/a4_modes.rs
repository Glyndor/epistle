//! Tests for the restore permission floor: every credential the operator
//! keeps on disk must come back from an archive at `0600`, and every
//! directory the restore creates must come back at `0700`, whatever mode
//! the archive header claimed and whatever umask the host runs with.
//!
//! The umask guard below is process-wide (`umask(2)` has no per-thread
//! form), so it is held only around the restore call itself.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use libc;

use super::lay_files;

/// Pin the process umask for the lifetime of the guard. `umask` is
/// process-wide, so the guard is scoped to the shortest window that needs
/// it: the call that creates files, not the assertions that read them back.
struct UmaskGuard {
	previous: libc::mode_t,
}

impl UmaskGuard {
	fn new(value: libc::mode_t) -> Self {
		// SAFETY: `umask` takes and returns a `mode_t` and touches no
		// memory the caller owns, so the call is sound from safe code.
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

/// Restore `entries` under umask 022 and hand the data dir back.
fn restore_under_permissive_umask(entries: &[(&str, u32, &[u8])]) -> tempfile::TempDir {
	let mask = UmaskGuard::new(0o022);
	let data_dir = tempfile::tempdir().expect("data_dir");
	let owned = entries
		.iter()
		.map(|(name, mode, content)| ((*name).to_string(), *mode, content.to_vec()))
		.collect::<Vec<_>>();
	lay_files(&owned, data_dir.path()).expect("lay_files");
	drop(mask);
	data_dir
}

/// The permission bits of `path`, masked to the nine that matter.
fn mode_of(path: &Path) -> u32 {
	fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

/// The global account store holds every account's credentials, so it must
/// land at 0600 even though the archive recorded it world-readable.
#[test]
fn global_accounts_toml_is_0600_under_umask_022() {
	let data_dir = restore_under_permissive_umask(&[("data/accounts.toml", 0o644, b"store\n")]);
	assert_eq!(
		mode_of(&data_dir.path().join("accounts.toml")),
		0o600,
		"global accounts.toml must not come back group- or world-readable"
	);
}

/// The `secrets/` tree is a credential by where it is stored: the database
/// password and the at-rest storage key live there, and the archive mode is
/// whatever umask the operator had when the tar was built.
#[test]
fn secrets_tree_is_0600_under_umask_022() {
	let data_dir = restore_under_permissive_umask(&[
		("data/secrets/epistle_db_password", 0o644, b"db-secret\n"),
		("data/secrets/storage.key", 0o644, b"at-rest-secret\n"),
		("data/secrets/internal/rotate.env", 0o644, b"TOKEN=abc\n"),
	]);
	for relative in [
		"secrets/epistle_db_password",
		"secrets/storage.key",
		"secrets/internal/rotate.env",
	] {
		assert_eq!(
			mode_of(&data_dir.path().join(relative)),
			0o600,
			"{relative} must be 0600 after restore"
		);
	}
}

/// Directories land at 0700 from creation. `create_dir_all` honours the
/// umask, so under 022 a fresh directory is 0755 until the restore
/// tightens it.
#[test]
fn restored_directories_are_0700_under_umask_022() {
	let data_dir = restore_under_permissive_umask(&[
		("data/secrets/internal/private.env", 0o600, b"x"),
		(
			"data/accounts/alice/new/0001.eml",
			0o644,
			b"Subject: hi\n\nbody",
		),
	]);
	for relative in ["secrets", "secrets/internal", "accounts", "accounts/alice"] {
		assert_eq!(
			mode_of(&data_dir.path().join(relative)),
			0o700,
			"{relative}/ must be 0700 from creation"
		);
	}
}

/// A `secrets/` directory that already exists at a permissive mode (left
/// behind by an earlier restore, or created by hand) must be tightened, not
/// merely created: `create_dir_all` is a no-op on a directory that is
/// already there.
#[test]
fn existing_lax_directory_is_tightened_on_restore() {
	let mask = UmaskGuard::new(0o022);
	let data_dir = tempfile::tempdir().expect("data_dir");
	let secrets = data_dir.path().join("secrets");
	fs::create_dir(&secrets).expect("mkdir");
	fs::set_permissions(&secrets, fs::Permissions::from_mode(0o755)).expect("chmod");
	lay_files(
		&[(
			"data/secrets/epistle_db_password".to_string(),
			0o644,
			b"s".to_vec(),
		)],
		data_dir.path(),
	)
	.expect("lay_files");
	drop(mask);
	assert_eq!(
		mode_of(&secrets),
		0o700,
		"an existing secrets/ must be tightened"
	);
}

/// The end-to-end guarantee: lay down a realistic tree the way a backup
/// built under umask 022 records it, then walk what landed on disk. Every
/// restored directory, and every restored credential, must be out of reach
/// of another user on the host. Ordinary mail is deliberately left alone:
/// the operator chmod'd it.
///
/// The credential list is written out here rather than asked of the
/// production classifier, so a regression that narrows the classifier
/// cannot narrow this test with it.
#[test]
fn no_restored_secret_is_reachable_by_other_users() {
	const CREDENTIALS: &[&str] = &[
		"accounts.toml",
		"secrets/epistle_db_password",
		"dkim-ed20240101.key",
		"accounts/alice/totp.toml",
		"tls/server.pem",
	];
	let data_dir = restore_under_permissive_umask(&[
		("data/accounts.toml", 0o644, b"global store\n"),
		("data/secrets/epistle_db_password", 0o644, b"db-secret\n"),
		("data/dkim-ed20240101.key", 0o644, b"FAKE-PEM-PRIVATE"),
		("data/accounts/alice/totp.toml", 0o644, b"seed\n"),
		("data/tls/server.pem", 0o644, b"-----BEGIN PRIVATE KEY-----"),
		(
			"data/accounts/alice/new/0001.eml",
			0o644,
			b"Subject: hi\n\nbody",
		),
	]);
	let root = data_dir.path();
	let mut offenders = Vec::new();
	walk(root, root, CREDENTIALS, &mut offenders);
	assert!(
		offenders.is_empty(),
		"restored credentials carry group or other bits: {offenders:?}"
	);
}

/// `config.toml` is the live server's runtime config: the operator chmod'd
/// the source whatever they wanted, but a permissive umask on the source
/// host (or a tampered archive header) must not bring the live config back
/// group- or world-readable. Owner bits stay, group and other are dropped.
/// Archived as 0664, a 0664 round-trip would let a co-tenant on a shared
/// host edit the live config; the floor sets it to 0600.
#[test]
fn root_config_toml_drops_group_and_other_bits() {
	let data_dir = restore_under_permissive_umask(&[("data/config.toml", 0o664, b"key = 1\n")]);
	let mode = mode_of(&data_dir.path().join("config.toml"));
	assert_eq!(
		mode & 0o077,
		0,
		"config.toml must land with no bits for group or other, got {mode:o}"
	);
	assert_eq!(
		mode, 0o600,
		"config.toml archived as 0664 must not come back group-writable, got {mode:o}"
	);
}

/// Executable archive bits at the root config path still earn the floor:
/// an archived `0700` lands as `0700`; the owner-execute bit survives. The
/// group/other bits are gone either way, so a multi-tenant host cannot
/// read or tamper with the live config.
#[test]
fn root_config_toml_keeps_owner_bits() {
	let data_dir = restore_under_permissive_umask(&[("data/config.toml", 0o700, b"key = 1\n")]);
	let mode = mode_of(&data_dir.path().join("config.toml"));
	assert_eq!(
		mode, 0o700,
		"an executable config.toml must keep its owner-execute bit, got {mode:o}"
	);
}

/// When the operator had no `data_dir` and the restore creates it, the
/// new `data_dir` lands at 0700 rather than the umask-honoured 0755 a
/// normal `mkdir` would produce. An existing operator-chmod'd `data_dir`
/// is left alone (the operator owns it): only a directory restore itself
/// created is tightened here.
#[test]
fn data_dir_created_by_restore_lands_at_0700() {
	let mask = UmaskGuard::new(0o022);
	// `data_dir` does NOT exist before restore. The restore will be the
	// first to create it via `create_dir_all`, and the umask is 022 so a
	// normal `mkdir` would leave the directory at 0755.
	let parent = tempfile::tempdir().expect("parent");
	let data_dir = parent.path().join("data");
	assert!(
		!data_dir.exists(),
		"precondition: data_dir must not exist yet"
	);
	let owned = vec![(
		"data/config.toml".to_string(),
		0o644_u32,
		b"key = 1\n".to_vec(),
	)];
	lay_files(&owned, &data_dir).expect("lay_files");
	drop(mask);
	assert_eq!(
		mode_of(&data_dir),
		0o700,
		"a data_dir the restore was the first to create must be 0700"
	);
}

/// When the operator already had a `data_dir`, restore leaves its mode
/// alone. The operator owns the directory; the restore only hardens the
/// tree below it. The chmod to 0700 is reserved for a data_dir restore
/// itself made.
#[test]
fn existing_data_dir_keeps_its_operator_mode() {
	let mask = UmaskGuard::new(0o022);
	let parent = tempfile::tempdir().expect("parent");
	let data_dir = parent.path().join("data");
	fs::create_dir(&data_dir).expect("mkdir data_dir");
	// Operator deliberately chmod's data_dir to something the restore
	// does not own: leave the choice in place.
	fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755)).expect("chmod");
	let owned = vec![(
		"data/config.toml".to_string(),
		0o644_u32,
		b"key = 1\n".to_vec(),
	)];
	lay_files(&owned, &data_dir).expect("lay_files");
	drop(mask);
	assert_eq!(
		mode_of(&data_dir),
		0o755,
		"an existing operator-chmod'd data_dir must not be re-chmod'd by restore"
	);
}

/// Record every restored entry that another user could reach, either because
/// it is a directory opened up or because it is on the credential list.
fn walk(root: &Path, dir: &Path, credentials: &[&str], offenders: &mut Vec<(String, u32)>) {
	let entries = fs::read_dir(dir).expect("read_dir");
	for entry in entries {
		let entry = entry.expect("entry");
		let path = entry.path();
		let relative = path.strip_prefix(root).expect("relative");
		let name = relative.display().to_string();
		let mode = mode_of(&path);
		if mode & 0o077 != 0 && (path.is_dir() || credentials.contains(&name.as_str())) {
			offenders.push((name, mode));
		}
		if path.is_dir() {
			walk(root, &path, credentials, offenders);
		}
	}
}
