//! The generated compose file read the one way every writer of it reads it: a
//! fifo at the path, a link to one, or a device is refused instead of waited
//! on, and the refusal reaches the command instead of being hidden behind an
//! empty map.

use super::*;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// The addresses `hosts_in_file` reads at `path` if it comes back inside five
/// seconds. A fifo with no writer releases the reader only when a writer
/// appears, so the deadline is the assertion, and the writer opened afterwards
/// is what lets the run finish instead of holding that thread for the rest of
/// it.
fn within(path: &Path) -> Result<BTreeMap<u16, IpAddr>, String> {
	use super::super::compose_publish;
	let (sender, receiver) = std::sync::mpsc::channel();
	let reading = path.to_path_buf();
	let reading_thread =
		std::thread::spawn(move || sender.send(compose_publish::hosts_in_file(&reading)));
	let value = receiver.recv_timeout(Duration::from_secs(5));
	if value.is_err() {
		drop(std::fs::OpenOptions::new().write(true).open(path));
	}
	let read = value.unwrap_or_else(|_| {
		panic!(
			"reading {} waited for a writer that never came",
			path.display()
		)
	});
	reading_thread
		.join()
		.expect("the reader thread panicked")
		.expect("the reader thread hung up");
	read
}

/// The path of the generated file inside a data directory that exists.
fn generated(dir: &Path) -> std::path::PathBuf {
	let path = super::super::compose::compose_file_path(dir);
	std::fs::create_dir_all(path.parent().expect("a data dir")).expect("compose dir");
	path
}

/// A fifo where the generated file belongs would hold a command, and the ones
/// that hold the configuration lock with it, until somebody opened the other
/// end.
#[test]
fn a_fifo_at_the_generated_compose_path_is_refused_instead_of_waited_on() {
	let dir = tempfile::tempdir().unwrap();
	let path = generated(dir.path());
	fifo_at(&path);
	let error = within(&path).expect_err("a fifo is not a file to read");
	assert!(error.contains("must be a regular file"), "{error}");
	assert!(error.contains(&path.display().to_string()), "{error}");
}

/// The same through a link, which is how a fifo gets past a check of the path
/// itself: the open follows the link, and the descriptor behind it is what says
/// whether it is a file.
#[test]
fn a_link_to_a_fifo_is_refused_instead_of_waited_on() {
	let dir = tempfile::tempdir().unwrap();
	let path = generated(dir.path());
	let pipe = dir.path().join("pipe");
	fifo_at(&pipe);
	std::os::unix::fs::symlink(&pipe, &path).unwrap();
	let error = within(&path).expect_err("a link to a fifo is not a file to read");
	assert!(error.contains("must be a regular file"), "{error}");
}

/// The generated file is routinely a link into another directory of the
/// installation, and every such install has to keep working.
#[test]
fn a_link_to_a_regular_file_is_followed() {
	let dir = tempfile::tempdir().unwrap();
	let path = generated(dir.path());
	let elsewhere = dir.path().join("generated.json");
	std::fs::write(
		&elsewhere,
		br#"{"services":{"mail":{"ports":["127.0.0.1:143:143"]}}}"#,
	)
	.unwrap();
	std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
	assert_eq!(
		within(&path).unwrap().get(&143).copied(),
		Some("127.0.0.1".parse().unwrap())
	);
}

/// An install without a compose file, and a device: the first is not a
/// failure, and the second answers every read and never ends one.
#[test]
fn a_missing_file_and_a_device_are_told_apart() {
	let dir = tempfile::tempdir().unwrap();
	assert_eq!(
		super::read(&dir.path().join("compose.yaml")).unwrap(),
		None,
		"a host install has no generated file to read"
	);
	let refused = within(Path::new("/dev/zero")).expect_err("a device is not a file");
	assert!(refused.contains("must be a regular file"), "{refused}");
}

/// `preview` and `prepare` read the same file again before the transaction,
/// under the lock this time, so they have to refuse it the same way instead of
/// wait for a writer while holding it.
#[test]
fn a_fifo_at_the_generated_compose_path_stops_the_map_readers_too() {
	use super::super::compose_publish;
	use crate::config::{Listener, ListenerKind};
	let dir = tempfile::tempdir().unwrap();
	fifo_at(&generated(dir.path()));
	let listeners = [Listener {
		kind: ListenerKind::Imaps,
		addr: "0.0.0.0".parse().unwrap(),
		port: Some(19993),
	}];
	let previewed = compose_publish::preview(dir.path(), &listeners, None)
		.expect_err("a fifo is not a file to read");
	assert!(
		previewed.to_string().contains("must be a regular file"),
		"{previewed}"
	);
	let Err(prepared) = compose_publish::prepare(dir.path(), &listeners, None) else {
		panic!("a fifo is not a file to read")
	};
	assert!(
		prepared.to_string().contains("must be a regular file"),
		"{prepared}"
	);
}
