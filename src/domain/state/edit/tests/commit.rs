//! The write itself: under the lock, atomic, owner-only, and nothing at all
//! for a change that changes nothing or a dry run.

use std::sync::{Arc, Barrier};

use super::super::super::file::StoredRole;
use super::super::super::tests::Fixture;
use super::*;

fn add(name: &str) -> Change {
	Change::Add {
		name: name.into(),
		role: StoredRole::Full,
		dkim: None,
		srs_secret: None,
	}
}

#[cfg(unix)]
fn identity(path: &std::path::Path) -> (u64, u32) {
	use std::os::unix::fs::MetadataExt;
	let metadata = std::fs::metadata(path).unwrap();
	(metadata.ino(), metadata.mode() & 0o777)
}

#[test]
fn the_first_write_starts_from_the_configuration_file() {
	let fixture = Fixture::new("send_only_domains = [\"other.example.org\"]\n");
	let config = fixture.load();
	let done = commit(&config, &add("new.example")).unwrap();
	assert_eq!(done.before, config.domain_seed.file());
	assert_eq!(
		done.after.domain("other.example.org").unwrap().role,
		StoredRole::SendOnly
	);
	assert_eq!(fixture.state().unwrap(), done.after, "what is on disk");
	assert_eq!(done.path, fixture.state_path());
}

#[cfg(unix)]
#[test]
fn a_write_replaces_the_file_atomically_and_owner_only() {
	let fixture = Fixture::new("");
	commit(&fixture.load(), &add("a.example")).unwrap();
	let (inode, mode) = identity(&fixture.state_path());
	assert_eq!(mode, 0o600);
	commit(&fixture.load(), &add("b.example")).unwrap();
	let (after, mode) = identity(&fixture.state_path());
	assert_ne!(after, inode, "a new file renamed over the old one");
	assert_eq!(mode, 0o600);
	let leftovers: Vec<_> = std::fs::read_dir(&fixture.data_dir)
		.unwrap()
		.filter_map(Result::ok)
		.map(|entry| entry.file_name().to_string_lossy().into_owned())
		.filter(|name| name.ends_with(".tmp"))
		.collect();
	assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[cfg(unix)]
#[test]
fn a_change_that_changes_nothing_writes_nothing() {
	let fixture = Fixture::new("");
	commit(&fixture.load(), &add("a.example")).unwrap();
	let before = identity(&fixture.state_path());
	let done = commit(
		&fixture.load(),
		&Change::SetEnabled {
			name: "a.example".into(),
			enabled: true,
		},
	)
	.unwrap();
	assert!(!done.changed);
	assert_eq!(identity(&fixture.state_path()), before);
}

#[test]
fn a_preview_and_a_refusal_write_nothing() {
	let fixture = Fixture::new("");
	let preview = preview(&fixture.load(), &add("a.example")).unwrap();
	assert!(preview.changed);
	assert!(preview.after.domain("a.example").is_some());
	assert!(fixture.state().is_none());
	assert!(commit(&fixture.load(), &add("bad name")).is_err());
	assert!(fixture.state().is_none());
}

#[test]
fn the_seed_is_written_once() {
	let fixture = Fixture::new("");
	assert!(seed(&fixture.load()).unwrap());
	commit(&fixture.load(), &add("a.example")).unwrap();
	assert!(!seed(&fixture.load()).unwrap(), "an existing file is kept");
	assert!(fixture.state().unwrap().domain("a.example").is_some());
}

#[test]
fn writers_that_race_lose_nothing() {
	let fixture = Arc::new(Fixture::new(""));
	let writers = 8;
	let barrier = Arc::new(Barrier::new(writers));
	let handles: Vec<_> = (0..writers)
		.map(|n| {
			let fixture = Arc::clone(&fixture);
			let barrier = Arc::clone(&barrier);
			std::thread::spawn(move || {
				let config = fixture.load();
				barrier.wait();
				commit(&config, &add(&format!("d{n}.example"))).unwrap();
			})
		})
		.collect();
	for handle in handles {
		handle.join().unwrap();
	}
	let names = fixture.state().unwrap().names();
	assert_eq!(names.len(), 2 + writers, "{names:?}");
	for n in 0..writers {
		assert!(names.contains(&format!("d{n}.example")), "{names:?}");
	}
}

#[test]
fn a_result_the_server_would_refuse_is_not_written() {
	let fixture = Fixture::new("[[listeners]]\nkind = \"smtp\"\nport = 2525\n");
	// Removing both domains leaves a server with listeners and no domain.
	commit(
		&fixture.load(),
		&Change::Remove {
			name: "example.org".into(),
		},
	)
	.unwrap();
	let before = fixture.state();
	let refusal = commit(
		&fixture.load(),
		&Change::Remove {
			name: "other.example.org".into(),
		},
	)
	.unwrap_err();
	assert!(matches!(refusal, EditError::Invalid(_)), "{refusal:?}");
	assert_eq!(fixture.state(), before);
}
