//! A stored resource is replaced in one step: a reader that opens the name
//! while a `PUT`, `COPY` or `MOVE` writes it sees the old file or the whole
//! new one, and no staging file is left behind.

use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::publish;

/// How many times the body is replaced while the reader runs.
const ROUNDS: usize = 40;

/// Large enough that a write which is not one step spans several pages.
const SIZE: usize = 4 * 1024 * 1024;

fn names(dir: &std::path::Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir)
		.unwrap()
		.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
		.collect();
	names.sort();
	names
}

#[test]
fn a_reader_never_sees_a_partial_body_while_a_put_replaces_it() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.build()
		.unwrap();
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("card.vcf");
	std::fs::write(&target, vec![b'a'; SIZE]).unwrap();
	let start = Barrier::new(2);
	let done = AtomicBool::new(false);
	std::thread::scope(|scope| {
		let reader = scope.spawn(|| {
			start.wait();
			let mut reads = 0u32;
			loop {
				let finished = done.load(Ordering::Acquire);
				let body = std::fs::read(&target).unwrap();
				assert_eq!(body.len(), SIZE, "a whole body, never a part");
				assert!(
					body.iter().all(|byte| *byte == body[0]),
					"the old body or the new one, never a mix"
				);
				reads += 1;
				if finished {
					return (reads, body[0]);
				}
			}
		});
		start.wait();
		for round in 0..ROUNDS {
			let byte = if round % 2 == 0 { b'b' } else { b'c' };
			runtime
				.block_on(publish::write(&target, &vec![byte; SIZE]))
				.unwrap();
		}
		done.store(true, Ordering::Release);
		let (reads, last) = reader.join().unwrap();
		assert!(reads >= 1);
		assert_eq!(last, b'c', "the last read comes after the last write");
	});
	assert_eq!(names(dir.path()), ["card.vcf"], "no staging file is left");
}

#[tokio::test]
async fn copy_and_move_replace_a_file_and_keep_its_mode() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let (source, copy, moved) = (
		dir.path().join("a.ics"),
		dir.path().join("b.ics"),
		dir.path().join("c.ics"),
	);
	std::fs::write(&source, "new").unwrap();
	std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
	std::fs::write(&copy, "old").unwrap();
	std::fs::write(&moved, "old").unwrap();
	publish::copy(&source, &copy).await.unwrap();
	assert_eq!(std::fs::read_to_string(&copy).unwrap(), "new");
	assert_eq!(
		std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
		0o640
	);
	publish::relocate(&source, &moved).await.unwrap();
	assert_eq!(std::fs::read_to_string(&moved).unwrap(), "new");
	assert!(!source.exists());
	assert_eq!(names(dir.path()), ["b.ics", "c.ics"]);
}

#[tokio::test]
async fn a_link_at_the_source_or_the_staging_name_is_not_followed() {
	let dir = tempfile::tempdir().unwrap();
	let outside = dir.path().join("outside");
	std::fs::write(&outside, "secret").unwrap();
	let link = dir.path().join("link.ics");
	std::os::unix::fs::symlink(&outside, &link).unwrap();
	let target = dir.path().join("target.ics");
	assert!(publish::copy(&link, &target).await.is_err());
	assert!(!target.exists(), "nothing is published from a link");
	publish::write(&link, b"new").await.unwrap();
	assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
	assert_eq!(std::fs::read_to_string(&link).unwrap(), "new");
	assert!(
		!std::fs::symlink_metadata(&link)
			.unwrap()
			.file_type()
			.is_symlink()
	);
}
