//! The database upgrade and the common configuration lock: the flow reads the
//! generated file, stops the stack, dumps the database and writes the file back
//! minutes later, so it takes the lock every other writer of that pair does.

use super::*;

use std::sync::mpsc;
use std::time::Duration;

/// A configuration with a data directory of its own and no stack in it.
fn config(dir: &std::path::Path) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	let text = format!(
		"hostname = 'mail.example.org'\ndomains = ['example.org']\ndata_dir = {:?}\n[database]\nurl = 'postgres://epistle@db/epistle?sslmode=require'\n[[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n",
		dir.join("data")
	);
	crate::storage::write_secret(&path, text.as_bytes()).unwrap();
	path
}

/// A held lock has to hold `db upgrade` too: a service edit made while the
/// dump runs would be lost by the write that follows it.
#[test]
fn the_upgrade_waits_for_the_common_lock_before_it_reads_the_stack() {
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let lock = dir.path().join(".epistle-config.lock");
	crate::storage::lock::create_private(&lock).unwrap();
	let held = crate::storage::lock::FileLock::acquire(&lock).unwrap();
	let (done, finished) = mpsc::channel();
	let waiting = path.clone();
	std::thread::spawn(move || {
		let loaded = Config::load(&waiting).expect("the fixture loads");
		done.send(run(&loaded, &waiting, DbCli::Upgrade, false))
			.unwrap();
	});
	let early = finished.recv_timeout(Duration::from_millis(200));
	assert!(
		matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
		"the upgrade escaped the shared lock: {early:?}"
	);
	drop(held);
	assert_eq!(
		finished
			.recv_timeout(Duration::from_secs(10))
			.expect("the upgrade must finish once the lock is free"),
		ExitCode::FAILURE,
		"there is no stack in the fixture, so the upgrade refuses after it took the lock"
	);
}

/// `db status` only asks the database a question, so it must not wait behind a
/// writer that is rewriting the stack.
#[test]
fn the_status_does_not_take_the_lock() {
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let lock = dir.path().join(".epistle-config.lock");
	crate::storage::lock::create_private(&lock).unwrap();
	let _held = crate::storage::lock::FileLock::acquire(&lock).unwrap();
	let loaded = Config::load(&path).expect("the fixture loads");
	assert_eq!(
		run(&loaded, &path, DbCli::Status, false),
		ExitCode::from(3),
		"a read-only query fails on the missing stack instead of waiting for the lock"
	);
}
