//! The bundle is written privately and never through a planted link.

use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

use super::*;
use crate::evidence::audit::tests::Fixture;
use crate::storage::MessageCrypto;

const MESSAGE: &str = "<1@example.org>";
const REFUSED_PATH: &str = "the output path already exists (or is a link)";

fn run(fixture: &Fixture, out: &Path) -> Result<Exported, BundleError> {
	export(
		fixture.root(),
		&MessageCrypto::disabled(),
		&Selector::MessageId(MESSAGE.into()),
		out,
	)
}

fn refusal(result: Result<Exported, BundleError>) -> String {
	match result {
		Err(BundleError::Refused(why)) => why,
		Err(BundleError::Io(error)) => format!("io: {:?}", error.kind()),
		Ok(_) => "exported".into(),
	}
}

fn mode(path: &Path) -> u32 {
	std::fs::symlink_metadata(path).expect("metadata").mode() & 0o777
}

#[test]
fn a_planted_link_to_a_directory_is_never_followed() {
	let fixture = Fixture::new();
	let scratch = tempfile::tempdir().expect("tempdir");
	let target = scratch.path().join("target");
	std::fs::create_dir(&target).expect("target");
	let out = scratch.path().join("bundle");
	symlink(&target, &out).expect("link");
	assert_eq!(refusal(run(&fixture, &out)), REFUSED_PATH);
	assert_eq!(std::fs::read_dir(&target).expect("read").count(), 0);
}

#[test]
fn a_planted_dangling_link_is_refused_and_nothing_is_created_behind_it() {
	let fixture = Fixture::new();
	let scratch = tempfile::tempdir().expect("tempdir");
	let target = scratch.path().join("not-there");
	let out = scratch.path().join("bundle");
	symlink(&target, &out).expect("link");
	assert_eq!(refusal(run(&fixture, &out)), REFUSED_PATH);
	assert!(!target.exists(), "the link was followed");
}

#[test]
fn a_missing_parent_is_not_created_for_the_bundle() {
	let fixture = Fixture::new();
	let scratch = tempfile::tempdir().expect("tempdir");
	let out = scratch.path().join("absent").join("bundle");
	assert_eq!(refusal(run(&fixture, &out)), "io: NotFound");
	assert!(!scratch.path().join("absent").exists());
}

#[test]
fn every_file_of_the_bundle_is_private() {
	let fixture = Fixture::new();
	let scratch = tempfile::tempdir().expect("tempdir");
	let out = scratch.path().join("bundle");
	run(&fixture, &out).expect("export");
	let mut seen = Vec::new();
	let mut pending = vec![out.clone()];
	while let Some(dir) = pending.pop() {
		assert_eq!(mode(&dir), 0o700, "{}", dir.display());
		for entry in std::fs::read_dir(&dir).expect("read") {
			let path = entry.expect("entry").path();
			if path.is_dir() {
				pending.push(path);
			} else {
				assert_eq!(mode(&path), 0o600, "{}", path.display());
				seen.push(path);
			}
		}
	}
	for name in ["README.md", "SHA256SUMS"] {
		assert!(seen.contains(&out.join(name)), "{name} is missing");
	}
}

#[test]
fn the_readme_and_the_sums_do_not_write_through_a_link() {
	let scratch = tempfile::tempdir().expect("tempdir");
	let bundle = scratch.path().join("bundle");
	std::fs::create_dir(&bundle).expect("bundle");
	let victim = scratch.path().join("victim");
	std::fs::write(&victim, "precious").expect("victim");
	for name in ["README.md", "SHA256SUMS"] {
		symlink(&victim, bundle.join(name)).expect("link");
	}
	assert!(readme::write(&bundle, &Exported::default()).is_err());
	assert!(sums::write(&bundle).is_err());
	assert_eq!(std::fs::read_to_string(&victim).expect("read"), "precious");
}

#[test]
fn a_bundle_of_countless_empty_directories_is_refused_by_count_not_by_exhaustion() {
	let fixture = Fixture::new();
	let scratch = tempfile::tempdir().expect("tempdir");
	let out = scratch.path().join("bundle");
	run(&fixture, &out).expect("export");
	let flood = out.join("flood");
	std::fs::create_dir(&flood).expect("dir");
	for index in 0..=MAX_FILES {
		std::fs::create_dir(flood.join(index.to_string())).expect("subdir");
	}
	let error = export::relative_files(&out).expect_err("a flood of directories");
	assert_eq!(error.to_string(), "too many files in the bundle");
}
