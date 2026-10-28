//! None of the five account commands that wait for the server's reload
//! may hold the lock on `accounts.toml` while it waits. A held lock
//! would stall the server's reload behind the CLI's wait and turn
//! every wait into a timeout.
//!
//! A thread plays the server: every few milliseconds it takes the
//! store lock when it is free, as a reload that edits the file would,
//! then runs one poll of a real file watcher over its own store, which
//! loads the command's write and publishes the status. The server must
//! load the write soon after it lands, well before the command's
//! timeout would have released a held lock.
//!
//! Lives in a sibling so `account_reload_tests.rs` stays under the
//! per-file code-line budget.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::with_timeout;
use crate::cli::account::{disable_with_store, enable_with_store, password_with_store};
use crate::cli::accounts::{add_with_display_name, remove_with_bayes};
use crate::config::Config;
use crate::directory_store::file_watcher::{PollEvent, PollTarget};
use crate::directory_store::removal::QueuePolicy;
use crate::directory_store::{AccountStore, DynamicAccount, FileWatcher, reload_fingerprint};
use crate::smtp::auth::tests::base::{fixture_password, hash, second_password};
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

/// Long enough for the simulated server to poll many times; a command
/// that holds the lock reaches it and returns before any load.
const TIMEOUT: Duration = Duration::from_secs(4);

fn config_for(data_dir: &Path) -> (tempfile::NamedTempFile, Config) {
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	std::io::Write::write_all(
		&mut file,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
			data_dir.canonicalize().expect("canonical")
		)
		.as_bytes(),
	)
	.expect("write config");
	let config = Config::load(file.path()).expect("config must load");
	(file, config)
}

fn open_store(data_dir: &Path) -> AccountStore {
	AccountStore::open(
		data_dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
}

/// A data dir with the dynamic account `bob` already on disk.
fn with_bob() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	open_store(dir.path())
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..DynamicAccount::default()
		})
		.expect("add bob");
	dir
}

/// Run `command` while a simulated server polls `data_dir`. Returns
/// the exit code and how long the server took to load the command's
/// write after it landed on disk. The command's own run time is not
/// the measure: hashing a password is slow in a debug build.
fn against_a_server(
	data_dir: &Path,
	command: impl FnOnce() -> ExitCode,
) -> (ExitCode, Option<Duration>) {
	let accounts = data_dir.join("accounts.toml");
	let mut watcher = FileWatcher::new(data_dir.to_path_buf(), Arc::new(open_store(data_dir)));
	// The first poll publishes the status, as the server does at start.
	watcher.poll();
	let lock: PathBuf = lock_path(&accounts);
	let stop = Arc::new(AtomicBool::new(false));
	let server = {
		let stop = Arc::clone(&stop);
		std::thread::spawn(move || {
			let initial = reload_fingerprint(&accounts);
			let (mut landed_at, mut load_delay) = (None, None);
			while !stop.load(Ordering::Relaxed) {
				// Seen without the lock: when the write reached the disk.
				// A write that lands after this check is loaded by the
				// poll below, so its delay counts from here.
				let checked_at = Instant::now();
				if landed_at.is_none() && reload_fingerprint(&accounts) != initial {
					landed_at = Some(checked_at);
				}
				// Never queue on the lock: a queued waiter is handed the
				// lock the moment the command's edit releases it, which
				// would let a reload slip in ahead of a lock the command
				// takes again for its wait.
				if let Some(held) = FileLock::try_acquire(&lock).expect("try the store lock") {
					let report = watcher.poll();
					drop(held);
					let loaded = report
						.events
						.contains(&PollEvent::Loaded(PollTarget::Accounts));
					if loaded && load_delay.is_none() {
						load_delay = Some(landed_at.unwrap_or(checked_at).elapsed());
					}
				}
				std::thread::sleep(Duration::from_millis(20));
			}
			load_delay
		})
	};
	let code = with_timeout(TIMEOUT, command);
	stop.store(true, Ordering::Relaxed);
	let load_delay = server.join().expect("server thread");
	(code, load_delay)
}

fn assert_not_blocked(command: &str, (code, load_delay): (ExitCode, Option<Duration>)) {
	assert_eq!(code, ExitCode::SUCCESS, "{command} must succeed");
	let load_delay = load_delay.expect("the server must load the write");
	assert!(
		load_delay < TIMEOUT / 2,
		"the server could not load the {command} write while the command waited"
	);
}

#[test]
fn add_does_not_hold_the_lock_while_it_waits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_file, config) = config_for(dir.path());
	let password = Cursor::new(format!("{}\n", fixture_password()));
	let result = against_a_server(dir.path(), || {
		add_with_display_name(
			&config,
			"carol",
			vec!["carol@example.org".to_string()],
			None,
			password,
			&mut std::io::sink(),
			false,
		)
	});
	assert_not_blocked("account add", result);
}

#[test]
fn remove_does_not_hold_the_lock_while_it_waits() {
	let dir = with_bob();
	let (_file, config) = config_for(dir.path());
	let store = Arc::new(open_store(dir.path()));
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let result = against_a_server(dir.path(), || {
		remove_with_bayes(
			&runtime,
			&store,
			&spool,
			&config,
			"bob",
			QueuePolicy::Discard,
			None,
			&mut out,
			&mut err,
			false,
		)
	});
	assert_not_blocked("account remove", result);
	assert!(err.is_empty(), "a loaded removal prints no note");
}

#[test]
fn password_does_not_hold_the_lock_while_it_waits() {
	let dir = with_bob();
	let store = open_store(dir.path());
	let password = Cursor::new(format!("{}\n", second_password()));
	let result = against_a_server(dir.path(), || {
		password_with_store(&store, "bob", password, &mut std::io::sink(), false)
	});
	assert_not_blocked("account password", result);
}

#[test]
fn disable_does_not_hold_the_lock_while_it_waits() {
	let dir = with_bob();
	let store = open_store(dir.path());
	let result = against_a_server(dir.path(), || {
		disable_with_store(&store, "bob", &mut std::io::sink(), false)
	});
	assert_not_blocked("account disable", result);
}

#[test]
fn enable_does_not_hold_the_lock_while_it_waits() {
	let dir = with_bob();
	let store = open_store(dir.path());
	store.set_disabled("bob", true).expect("disable bob first");
	let result = against_a_server(dir.path(), || {
		enable_with_store(&store, "bob", &mut std::io::sink(), false)
	});
	assert_not_blocked("account enable", result);
}
