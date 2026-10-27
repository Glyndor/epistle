//! Stack writers must load the configuration after taking the service lock.

use super::*;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn resource_edits_wait_for_the_common_lock_before_loading_config() {
	let dir = tempfile::tempdir().unwrap();
	let config = dir.path().join("mail.toml");
	let text = format!(
		"hostname = 'mail.example.org'\ndomains = ['example.org']\ndata_dir = {:?}\n",
		dir.path()
	);
	crate::storage::write_secret(&config, text.as_bytes()).unwrap();
	let compose = dir.path().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	let before = br#"{"services":{"mail":{"pids_limit":100}}}"#;
	std::fs::write(&compose, before).unwrap();
	let held = crate::cli::service_lock::acquire(&config).unwrap();
	std::thread::scope(|scope| {
		let (tx, rx) = mpsc::channel();
		let path = &config;
		scope.spawn(move || {
			let cli = StackCli::Resources {
				action: Some(crate::cli::stack::resources::ResourcesCli::Set {
					service: "mail".into(),
					memory: None,
					pids: Some(123),
				}),
				json: false,
			};
			tx.send(run_from_path(path, cli, false)).unwrap();
		});
		let early = rx.recv_timeout(Duration::from_millis(200));
		// This intervening edit must be seen after the lock is released.
		std::fs::write(&config, "invalid config").unwrap();
		drop(held);
		assert!(
			matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
			"{early:?}"
		);
		assert_eq!(
			rx.recv_timeout(Duration::from_secs(10)).unwrap(),
			ExitCode::FAILURE
		);
	});
	assert_eq!(std::fs::read(&compose).unwrap(), before);
}

/// A stack writer reads its configuration with the common lock in hand, so a
/// fifo at that path, or behind a symlink, has to be refused by name inside a
/// few seconds: waiting for a writer that may never come would keep every
/// other writer of the directory out for as long as it lasts.
#[test]
#[cfg(unix)]
fn a_fifo_at_the_config_path_stops_a_stack_writer_and_frees_the_lock() {
	for linked in [false, true] {
		for update in [false, true] {
			let dir = tempfile::tempdir().unwrap();
			let config = dir.path().join("mail.toml");
			let fifo = dir.path().join("mail.toml.fifo");
			crate::cli::init::compose_read::fifo_at(&fifo);
			if linked {
				std::os::unix::fs::symlink(&fifo, &config).unwrap();
			} else {
				std::fs::rename(&fifo, &config).unwrap();
			}
			let label = format!(
				"stack {} on a {} configuration",
				if update { "update" } else { "resources set" },
				if linked { "linked" } else { "direct" }
			);
			assert_eq!(
				run_within(&config, &fifo, update),
				ExitCode::FAILURE,
				"{label}"
			);
			assert!(
				free_within(&dir.path().join(".epistle-config.lock")),
				"{label} must leave the common lock free"
			);
		}
	}
}

/// A configuration behind a symlink is one the loader has always read, and a
/// verified reader that refused links would turn that install into an error on
/// every stack write. The link still loads and the limit lands on the file.
#[test]
#[cfg(unix)]
fn a_configuration_behind_a_symlink_still_loads_for_a_stack_writer() {
	let dir = tempfile::tempdir().unwrap();
	write_compose(dir.path());
	let elsewhere = dir.path().join("elsewhere.toml");
	let text = config_text(dir.path());
	crate::storage::write_secret(&elsewhere, text.as_bytes()).unwrap();
	let linked = dir.path().join("mail.toml");
	std::os::unix::fs::symlink(&elsewhere, &linked).unwrap();
	assert_eq!(run_from_path(&linked, set_pids(), false), ExitCode::SUCCESS);
	let compose = dir.path().join("compose/compose.yaml");
	assert!(
		std::fs::read_to_string(&compose)
			.unwrap()
			.contains("\"pids_limit\": 123"),
		"a linked configuration must still be able to write the file"
	);
}

/// The lock that guards the generated file can be kept by an older command, or
/// by a tool that only respects that one. A rewrite that can not take it stops
/// naming the file, and the common lock it was holding is free again, so the
/// next writer is not kept out behind a command that already stopped.
#[test]
fn a_refused_compose_lock_frees_the_common_lock() {
	let dir = tempfile::tempdir().unwrap();
	let config = install(dir.path());
	// The lock file is a directory, so the open fails at once: the same
	// refusal a holder that never finishes ends in, without a wait to sit
	// through.
	std::fs::create_dir_all(crate::storage::locked::lock_path(&compose_in(dir.path()))).unwrap();
	assert_eq!(run_from_path(&config, set_pids(), false), ExitCode::FAILURE);
	assert!(
		free_within(&dir.path().join(".epistle-config.lock")),
		"a command that stops on the generated file's lock must leave the common lock free"
	);
}

/// Whether `lock` can be taken within a few seconds. A command that kept the
/// common lock would hold it for as long as it ran, so the wait here covers a
/// descriptor copy another test's `fork` leaves behind for a moment and not a
/// command that never lets go.
fn free_within(lock: &Path) -> bool {
	let deadline = std::time::Instant::now() + Duration::from_secs(5);
	loop {
		match crate::storage::lock::FileLock::try_acquire(lock) {
			Ok(Some(_)) => return true,
			Ok(None) => {}
			Err(error) => panic!("cannot open {}: {error}", lock.display()),
		}
		if std::time::Instant::now() >= deadline {
			return false;
		}
		std::thread::sleep(Duration::from_millis(20));
	}
}

/// A configuration file and the generated file of an install whose `data_dir`
/// is `dir`, so a stack writer has both of them where it looks.
fn install(dir: &Path) -> PathBuf {
	let config = dir.join("mail.toml");
	let text = config_text(dir);
	crate::storage::write_secret(&config, text.as_bytes()).unwrap();
	write_compose(dir);
	config
}

fn config_text(dir: &Path) -> String {
	format!(
		"hostname = 'mail.example.org'\ndomains = ['example.org']\ndata_dir = {:?}\n",
		dir.to_str().unwrap()
	)
}

fn write_compose(dir: &Path) {
	let compose = compose_in(dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(&compose, crate::cli::init::rendered_for_tests(dir, None)).unwrap();
}

fn compose_in(dir: &Path) -> PathBuf {
	dir.join("compose/compose.yaml")
}

fn set_pids() -> StackCli {
	StackCli::Resources {
		action: Some(crate::cli::stack::resources::ResourcesCli::Set {
			service: "mail".into(),
			memory: None,
			pids: Some(123),
		}),
		json: false,
	}
}

/// `run_from_path` if it comes back inside five seconds. A fifo with no writer
/// releases its reader only when a writer appears, so the deadline is the
/// assertion, and the writer opened afterwards is what lets a run that waited
/// finish instead of holding this thread for the rest of the suite.
#[cfg(unix)]
fn run_within(config: &Path, fifo: &Path, update: bool) -> ExitCode {
	let (sender, receiver) = mpsc::channel();
	let reading = config.to_path_buf();
	let release = fifo.to_path_buf();
	let running = std::thread::spawn(move || {
		let cli = if update { StackCli::Update } else { set_pids() };
		sender.send(run_from_path(&reading, cli, false)).ok();
	});
	let value = receiver.recv_timeout(Duration::from_secs(5));
	if value.is_err() {
		drop(std::fs::OpenOptions::new().write(true).open(&release));
	}
	let code = value
		.unwrap_or_else(|_| panic!("{} waited for a writer that never came", config.display()));
	running.join().expect("the command thread panicked");
	code
}
