//! A domain's key files: made once, never replaced, never shared.

use super::*;

const NOW: u64 = 20_000 * 86_400 + 5;

fn public(file: &Path) -> String {
	let signer = Signer::load("x", file).expect("the key loads");
	signer.dns_record_value()
}

/// The day the file was written, read back from the file system.
fn file_day(file: &Path) -> u64 {
	let modified = std::fs::metadata(file)
		.expect("meta")
		.modified()
		.expect("mtime");
	modified
		.duration_since(std::time::UNIX_EPOCH)
		.expect("after the epoch")
		.as_secs()
		/ 86_400
}

#[test]
fn a_domain_gets_an_ed25519_key_and_names_its_selector_after_the_day() {
	let dir = tempfile::tempdir().expect("dir");
	let (keys, created) = ensure(dir.path(), "Example.org", false, NOW, &[]).expect("keys");
	assert_eq!(keys.selector, format!("own{}", file_day(&keys.key_file)));
	assert_eq!(
		keys.key_file,
		dir.path().join("keys/dkim/example.org/ed25519.pem")
	);
	assert_eq!(created, vec![keys.key_file.clone()]);
	assert!(keys.rsa.is_none());
	public(&keys.key_file);
}

#[test]
fn dual_signing_adds_an_rsa_key_under_its_own_selector() {
	let dir = tempfile::tempdir().expect("dir");
	let (keys, created) = ensure(dir.path(), "example.org", true, NOW, &[]).expect("keys");
	let (selector, file) = keys.rsa.expect("an rsa key");
	assert_eq!(selector, format!("ownrsa{}", file_day(&file)));
	assert_eq!(file, dir.path().join("keys/dkim/example.org/rsa.pem"));
	assert_eq!(created.len(), 2);
	crate::dkim::rsa_record_value(&file).expect("the rsa key loads");
}

#[test]
fn two_domains_never_get_the_same_key() {
	let dir = tempfile::tempdir().expect("dir");
	let (a, _) = ensure(dir.path(), "a.example", false, NOW, &[]).expect("a");
	let (b, _) = ensure(dir.path(), "b.example", false, NOW, &[]).expect("b");
	assert_ne!(public(&a.key_file), public(&b.key_file));
}

#[test]
fn running_it_again_keeps_the_key_and_the_selector() {
	let dir = tempfile::tempdir().expect("dir");
	let (first, _) = ensure(dir.path(), "example.org", false, NOW, &[]).expect("first");
	let before = public(&first.key_file);
	// A later day: the file decides the selector, not the clock.
	let (again, created) =
		ensure(dir.path(), "example.org", false, NOW + 9 * 86_400, &[]).expect("again");
	assert_eq!(again, first);
	assert!(created.is_empty(), "nothing is written the second time");
	assert_eq!(public(&again.key_file), before);
}

#[test]
fn a_key_file_that_does_not_load_is_never_replaced() {
	let dir = tempfile::tempdir().expect("dir");
	let target = dir.path().join("keys/dkim/example.org");
	std::fs::create_dir_all(&target).expect("dir");
	std::fs::write(target.join("ed25519.pem"), "not a key").expect("write");
	let error = ensure(dir.path(), "example.org", false, NOW, &[]).expect_err("refused");
	assert!(error.contains("does not load"), "{error}");
	assert_eq!(
		std::fs::read_to_string(target.join("ed25519.pem")).expect("read"),
		"not a key"
	);
}

#[test]
fn a_name_that_could_leave_the_key_directory_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	for name in ["../escape", "a/b", "", ".hidden", "a..b", "a b"] {
		assert!(
			key_dir(dir.path(), name).is_err(),
			"{name:?} must be refused"
		);
	}
	assert!(key_dir(dir.path(), "xn--e1afmkfd.example").is_ok());
}

#[cfg(unix)]
#[test]
fn the_key_and_its_directory_are_private() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("dir");
	let (keys, _) = ensure(dir.path(), "example.org", false, NOW, &[]).expect("keys");
	let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
	assert_eq!(mode(&keys.key_file), 0o600);
	assert_eq!(mode(keys.key_file.parent().expect("dir")), 0o700);
}

#[test]
fn removing_what_was_created_leaves_a_file_that_was_there() {
	let dir = tempfile::tempdir().expect("dir");
	let (keys, created) = ensure(dir.path(), "example.org", false, NOW, &[]).expect("keys");
	remove(&created);
	assert!(!keys.key_file.exists());
	let (keys, _) = ensure(dir.path(), "example.org", false, NOW, &[]).expect("keys");
	remove(&[]);
	assert!(keys.key_file.exists());
}

#[test]
fn runs_that_race_for_one_domain_end_with_one_key_and_never_replace_it() {
	let dir = tempfile::tempdir().expect("dir");
	let data = dir.path().to_path_buf();
	let results: Vec<_> = (0..8)
		.map(|_| {
			let data = data.clone();
			std::thread::spawn(move || ensure(&data, "example.org", false, NOW, &[]).expect("keys"))
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|handle| handle.join().expect("thread"))
		.collect();
	let made: usize = results.iter().map(|(_, created)| created.len()).sum();
	assert_eq!(made, 1, "exactly one run installed the key");
	let key = public(&results[0].0.key_file);
	assert!(
		results
			.iter()
			.all(|(keys, _)| public(&keys.key_file) == key)
	);
}

#[test]
fn an_installed_key_is_never_replaced_by_a_run_that_found_the_path_empty() {
	let dir = tempfile::tempdir().expect("dir");
	let path = dir.path().join("ed25519.pem");
	assert_eq!(install_new(&path, "first"), Ok(true));
	assert_eq!(install_new(&path, "second"), Ok(false));
	assert_eq!(std::fs::read_to_string(&path).expect("read"), "first");
	let leftovers = std::fs::read_dir(dir.path()).expect("dir").count();
	assert_eq!(leftovers, 1, "no staged copy is left behind");
}
