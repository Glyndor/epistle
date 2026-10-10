//! Tests for generated files, permissions, atomic writes, and password storage.

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::test_support::{fresh_dir, load_for_test, local_error_name, open_store_for_test};
use super::{ACCOUNT_NAME, DEFAULT_PORT_BASE, LocalError, layout, prepare};

/// Walk every entry under `root`, returning a sorted list of paths.
fn list_under(root: &Path) -> Vec<std::path::PathBuf> {
	let mut out = Vec::new();
	let mut stack = vec![root.to_path_buf()];
	while let Some(top) = stack.pop() {
		let entries = match std::fs::read_dir(&top) {
			Ok(entries) => entries,
			Err(_) => continue,
		};
		for entry in entries.flatten() {
			let path = entry.path();
			out.push(path.clone());
			if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
				stack.push(path);
			}
		}
	}
	out.sort();
	out
}

/// SHA-256 of the bytes of `path`, used to assert idempotence.
fn sha256(path: &Path) -> Vec<u8> {
	use ring::digest::{SHA256, digest};
	let bytes = std::fs::read(path).expect("read for hash");
	digest(&SHA256, &bytes).as_ref().to_vec()
}

/// Pin: on the first run on an empty directory the marker, `mail.toml`,
/// cert, key and DKIM key all exist; on Unix every file is `0600` and
/// every directory `0700`; `Config::load` and the directory store accept
/// the generated `mail.toml`.
#[test]
fn layout_marks_marker_files_and_permissions() {
	let dir = fresh_dir("layout");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");

	// Marker, config, cert, key and DKIM key all present.
	let expected_files = [
		".epistle-local",
		"mail.toml",
		"cert.pem",
		"key.pem",
		"dkim.pem",
	];
	for name in expected_files {
		assert!(
			dir.path().join(name).exists(),
			"missing {name} under {}",
			dir.path().display()
		);
	}

	// Per-file / per-directory permissions on Unix.
	#[cfg(unix)]
	{
		let file_modes = expected_files
			.iter()
			.map(|name| {
				(
					name,
					std::fs::metadata(dir.path().join(name))
						.unwrap()
						.permissions()
						.mode() & 0o777,
				)
			})
			.collect::<Vec<_>>();
		for (name, mode) in &file_modes {
			assert_eq!(*mode, 0o600, "{name} must be 0600, got {:o}", mode);
		}
		let data_mode = std::fs::metadata(dir.path().join("data"))
			.unwrap()
			.permissions()
			.mode() & 0o777;
		assert_eq!(data_mode, 0o700, "data/ must be 0700, got {data_mode:o}");
		let accounts_mode = std::fs::metadata(dir.path().join("data").join("accounts.toml"))
			.unwrap()
			.permissions()
			.mode() & 0o777;
		assert_eq!(accounts_mode, 0o600, "accounts.toml must be 0600");
	}

	// `Config::load` round-trips the generated `mail.toml`, and the
	// `AccountStore` opens the data directory.
	let _ = load_for_test(&dir.path().join("mail.toml")).expect("mail.toml loads");
	let _ = open_store_for_test(&dir.path().join("data")).expect("account store opens");

	// The banner carries the account name and the password ONCE.
	assert_eq!(prepared.account, ACCOUNT_NAME);
	assert!(
		prepared.password.is_some(),
		"first run must mint a password"
	);
}

/// Pin: two preparations on the same directory produce the same SHA-256
/// for every generated file, and the second preparation reuses what the
/// first one wrote.
#[test]
fn idempotence_second_run_reuses_every_generated_file() {
	let dir = fresh_dir("idempotence");
	prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let first_hashes: Vec<(String, Vec<u8>)> = ["mail.toml", "cert.pem", "key.pem", "dkim.pem"]
		.iter()
		.map(|name| (name.to_string(), sha256(&dir.path().join(name))))
		.collect();
	let first_accounts = std::fs::read_to_string(dir.path().join("data").join("accounts.toml"))
		.expect("read accounts.toml");

	let second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("second prepare");
	let second_hashes: Vec<(String, Vec<u8>)> = ["mail.toml", "cert.pem", "key.pem", "dkim.pem"]
		.iter()
		.map(|name| (name.to_string(), sha256(&dir.path().join(name))))
		.collect();
	let second_accounts = std::fs::read_to_string(dir.path().join("data").join("accounts.toml"))
		.expect("read accounts.toml");

	// `accounts.toml` carries the password hash; an `assert_eq!`
	// on the file contents would Debug-print both copies on
	// mismatch, dumping the hash into the CI log. The boolean
	// form pins the same invariant without carrying the secret.
	assert_eq!(
		first_hashes, second_hashes,
		"every file must be byte-identical"
	);
	assert!(
		first_accounts == second_accounts,
		"accounts.toml must not change"
	);
	assert!(
		second.password.is_none(),
		"second run must NOT regenerate the password"
	);
}

/// Pin: a directory that holds one unrelated file and no marker is
/// refused with the exact contract text and the directory still holds
/// exactly that one file afterwards. The same directory with the marker
/// added is accepted.
#[test]
fn refusal_dir_with_unrelated_content_is_refused_then_accepted_with_marker() {
	let dir = fresh_dir("refusal");
	let stray = dir.path().join("stray.txt");
	std::fs::write(&stray, b"unrelated").expect("write stray");

	let first = prepare(dir.path(), DEFAULT_PORT_BASE);
	match first {
		Err(LocalError::NotEmpty(path)) => {
			assert_eq!(
				path,
				dir.path(),
				"NotEmpty path must be the directory itself"
			);
		}
		// The `Ok` arm carries a `Prepared`, whose `Debug` would echo
		// the freshly generated `Config` and through it the API
		// token hash. The panic must name the outcome, never the
		// value, so a regression here does not dump the secret into
		// the CI log.
		Ok(_) => panic!("expected NotEmpty, got Ok"),
		Err(other) => panic!("expected NotEmpty, got {}", local_error_name(&other)),
	}

	// The unrelated file is still exactly there: nothing was written.
	let after_refuse = std::fs::read_dir(dir.path())
		.expect("readdir")
		.flatten()
		.map(|entry| entry.file_name())
		.collect::<Vec<_>>();
	assert_eq!(after_refuse.len(), 1, "only the stray file may remain");
	assert_eq!(after_refuse[0].to_str(), Some("stray.txt"));

	// Add the marker and the same directory is now accepted. The marker
	// alone is not enough for the reuse path (the contract's idempotence
	// rule needs every artifact present), so this run generates; the
	// acceptance the contract pins is that `prepare` does NOT refuse.
	std::fs::write(dir.path().join(".epistle-local"), b"").expect("write marker");
	let second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("accepted with marker");
	assert!(
		second.password.is_some(),
		"marker added to an empty dir triggers Generate, so a password is minted"
	);
}

/// Pin: no file under `<DIR>` contains the generated password bytes.
/// The password comes from the same generator the rest of the code uses
/// for seeded credentials; a test never passes a literal.
#[test]
fn password_never_written_in_clear_anywhere_under_dir() {
	let dir = fresh_dir("nopwd");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");
	let password = prepared.password.expect("first run mints a password");
	assert!(
		password.len() >= 24,
		"password must be at least 24 chars of the policy alphabet"
	);

	// Walk the tree and assert no file contains the password bytes.
	let mut found_in: Vec<std::path::PathBuf> = Vec::new();
	for entry in list_under(dir.path()) {
		if entry.is_dir() {
			continue;
		}
		let bytes = match std::fs::read(&entry) {
			Ok(bytes) => bytes,
			Err(_) => continue,
		};
		if bytes
			.windows(password.len())
			.any(|window| window == password.as_bytes())
		{
			found_in.push(entry);
		}
	}
	assert!(
		found_in.is_empty(),
		"password bytes appeared in: {:?}",
		found_in
	);
}

/// Pin: `write_with_replace` over a target that exists with mode `0644`
/// narrows it to `0600` and leaves no temporary file behind. The narrow
/// mode is applied at open time, not by a follow-up `chmod`: an open
/// with the default mode followed by `chmod` would leave the wider
/// mode on disk for the duration of the write, and on disk if a crash
/// interrupted the run between the open and the `chmod`.
#[cfg(unix)]
#[test]
fn replace_over_existing_world_readable_file_narrows_to_0600_and_cleans_up_temp() {
	let dir = fresh_dir("replace-mode");
	let target = dir.path().join("mail.toml");

	// Pre-create the target with mode 0644 (the wider mode the fix is
	// closing) so the test exercises the narrow-on-replace path.
	std::fs::write(&target, b"old").expect("write old");
	std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
	let mode_before = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode_before, 0o644, "fixture must start at 0644");

	// The replacement writes a credential file with mode 0600.
	layout::write_with_replace(&target, b"new", 0o600).expect("replace");

	// Mode is narrowed on the now-replaced file.
	let mode_after = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
	assert_eq!(
		mode_after, 0o600,
		"replaced file must be 0600, got {mode_after:o}"
	);
	assert_eq!(
		std::fs::read(&target).expect("read after replace"),
		b"new",
		"the contents must be the new payload, not a truncated mix of old and new"
	);

	// No temporary file remains. `write_with_replace` writes through a
	// sibling `<dir>/.mail.toml-<pid>-<n>.tmp` and renames over the
	// target, so a half-written `mail.toml` cannot outlive the call.
	let leftover: Vec<_> = std::fs::read_dir(dir.path())
		.expect("readdir")
		.flatten()
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.collect();
	assert!(
		leftover.is_empty(),
		"the sibling temporary must be renamed over the target, found {leftover:?}"
	);
}

/// Pin: `write_with_replace` over a path whose parent directory does
/// not exist yet still fails closed, because the temporary file lives
/// in the same directory as the target and the rename cannot cross
/// directories.
#[cfg(unix)]
#[test]
fn replace_into_missing_parent_directory_errors() {
	let dir = fresh_dir("replace-missing-parent");
	let target = dir.path().join("nope").join("mail.toml");
	let result = layout::write_with_replace(&target, b"x", 0o600);
	assert!(
		result.is_err(),
		"replace into a missing parent must error, got {result:?}"
	);
	// Neither the parent nor the target was created on the error path.
	assert!(
		!dir.path().join("nope").exists(),
		"parent must not be created"
	);
	assert!(!target.exists(), "target must not be created");
}

/// Pin: a fresh replace over a non-existent target still produces a
/// 0600 file with the right contents. The atomic-replace path must
/// work for the first write, not only the overwrite case.
#[cfg(unix)]
#[test]
fn replace_over_missing_file_creates_with_0600() {
	let dir = fresh_dir("replace-fresh");
	let target = dir.path().join("mail.toml");
	layout::write_with_replace(&target, b"fresh", 0o600).expect("fresh replace");
	let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600, "fresh replace must produce 0600, got {mode:o}");
	assert_eq!(std::fs::read(&target).expect("read"), b"fresh");
}

/// Pin: the temporary file `write_with_replace` writes through is
/// 0600 from the moment `open_replace_temp` creates it. The trailing
/// `set_mode` after the rename would mask a buggy open (it would
/// narrow the target to 0600 regardless), so the assertion looks at
/// the temp BEFORE the rename happens; with `.mode(0o666)` slipped in
/// here, this test fails with the literal mode it read.
#[cfg(unix)]
#[test]
fn replace_temp_file_is_created_with_mode_0600_from_first_byte() {
	let dir = fresh_dir("replace-temp-mode");
	let target = dir.path().join("mail.toml");
	let (file, temp_path) =
		layout::open_replace_temp(dir.path(), &target, 0o600).expect("open temp");

	let mode = std::fs::metadata(&temp_path)
		.expect("stat temp")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o600,
		"temp file must be 0600 from creation, got {mode:o}"
	);

	drop(file);
	let _ = std::fs::remove_file(&temp_path);
}
