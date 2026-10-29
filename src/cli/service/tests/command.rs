use super::*;

#[cfg(unix)]
use crate::cli::init::compose_read::fifo_at;

pub(super) fn fixture() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	std::fs::write(file.path(), format!("# deployment\nhostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n\n# public socket\n[[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n", dir.path().canonicalize().unwrap())).unwrap();
	(dir, file)
}

/// `execute_with(path, action)` if it comes back inside five seconds. A fifo
/// with no writer releases its reader only when a writer appears, so the
/// deadline is the assertion, and the writer opened afterwards is what lets a
/// run that waited finish instead of holding this thread for the rest of the
/// suite.
#[cfg(unix)]
fn within(path: &Path, fifo: &Path, action: ServiceCli) -> Result<ExitCode, String> {
	use std::sync::mpsc;
	use std::time::Duration;
	let (sender, receiver) = mpsc::channel();
	let reading = path.to_path_buf();
	let release = fifo.to_path_buf();
	let running = std::thread::spawn(move || {
		sender
			.send(
				execute_with(
					&reading,
					action,
					false,
					false,
					&mut Vec::new(),
					&mut Vec::new(),
					|_, _| panic!("a refused configuration must not reach the stack"),
				)
				.map_err(|error| error.to_string()),
			)
			.ok();
	});
	let value = receiver.recv_timeout(Duration::from_secs(5));
	if value.is_err() {
		drop(std::fs::OpenOptions::new().write(true).open(&release));
	}
	let result =
		value.unwrap_or_else(|_| panic!("{} waited for a writer that never came", path.display()));
	running.join().expect("the command thread panicked");
	result
}

#[test]
fn service_command_dry_run_then_change_and_no_op() {
	let (_dir, file) = fixture();
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let action = || ServiceCli::Enable {
		name: ServiceName::Webdav,
	};
	let result = execute_with(
		file.path(),
		action(),
		true,
		false,
		&mut out,
		&mut status,
		|_, _| panic!("dry-run must not restart"),
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let expected = super::super::super::service::edit::listener_document(
		file.path(),
		ListenerKind::WebDav,
		true,
	)
	.unwrap()
	.0
	.dry_run()
	.unwrap();
	assert_eq!(
		String::from_utf8(out.clone()).unwrap(),
		expected,
		"service dry-run must print the engine diff"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == before,
		"service dry-run must preserve config bytes"
	);
	assert!(status.is_empty());
	out.clear();
	assert_eq!(
		execute_with(
			file.path(),
			action(),
			false,
			false,
			&mut out,
			&mut status,
			|_, _| panic!("host install must not invoke stack")
		)
		.unwrap(),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(status.clone()).unwrap(),
		"webdav enabled.\nThe server must be restarted.\n"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap()
			== format!("{before}\n[[listeners]]\nkind = \"web-dav\"\naddr = \"127.0.0.1\"\n"),
		"service command must preserve exact commented text"
	);
	status.clear();
	let modified = std::fs::metadata(file.path()).unwrap().modified().unwrap();
	assert_eq!(
		execute_with(
			file.path(),
			action(),
			false,
			false,
			&mut out,
			&mut status,
			|_, _| panic!("no-op must not restart")
		)
		.unwrap(),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"webdav is already enabled; nothing changed.\n"
	);
	assert_eq!(
		std::fs::metadata(file.path()).unwrap().modified().unwrap(),
		modified
	);
}

#[test]
/// A published port only changes when the container is recreated: a plain
/// restart keeps the old port forwarding, so a disabled listener would stay
/// reachable. The stack is brought up again, which recreates mail.
fn service_command_updates_ports_and_recreates_mail() {
	let (_dir, file) = fixture();
	// IMAP is a STARTTLS listener, so the loader wants certificates before it
	// binds one outside loopback.
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("[tls]\ncert_file = '/cert.pem'\nkey_file = '/key.pem'\n");
	std::fs::write(file.path(), text).unwrap();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"ports":["25:25"],"image":"keep"}}}"#,
	)
	.unwrap();
	let code = execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Imap,
		},
		false,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|config, action| {
			assert_eq!(config.listeners.len(), 2);
			assert!(
				matches!(&action, super::super::super::stack::StackAction::Recreate { service } if service == "mail"),
				"a port change must recreate mail, not restart it: {action:?}"
			);
			ExitCode::from(7)
		},
	)
	.unwrap();
	assert_eq!(
		code,
		ExitCode::from(7),
		"service command must propagate restart failure"
	);
	let compose: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(compose).unwrap()).unwrap();
	assert_eq!(
		compose["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "143:143"])
	);
	assert_eq!(compose["services"]["mail"]["image"], "keep");
}

#[test]
fn service_writers_wait_and_read_the_latest_config_under_the_common_lock() {
	use std::sync::mpsc;
	use std::time::Duration;
	for action in [
		ServiceCli::Set {
			name: ServiceName::Smtp,
			bind: None,
			port: Some(2525),
		},
		ServiceCli::Enable {
			name: ServiceName::Webdav,
		},
		ServiceCli::Disable {
			name: ServiceName::Webdav,
		},
	] {
		let (dir, file) = fixture();
		let lock_path = dir.path().join(".epistle-config.lock");
		crate::storage::lock::create_private(&lock_path).unwrap();
		let held = crate::storage::lock::FileLock::acquire(&lock_path).unwrap();
		std::thread::scope(|scope| {
			let (started, starting) = mpsc::channel();
			let (done, result) = mpsc::channel();
			let path = file.path();
			scope.spawn(move || {
				started.send(()).unwrap();
				let code = execute_with(
					path,
					action,
					false,
					false,
					&mut Vec::new(),
					&mut Vec::new(),
					|_, _| ExitCode::SUCCESS,
				);
				done.send(code).unwrap();
			});
			starting.recv().unwrap();
			let early = result.recv_timeout(Duration::from_millis(200));
			if !matches!(early, Err(mpsc::RecvTimeoutError::Timeout)) {
				drop(held);
				assert!(
					matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
					"the writer escaped the shared lock: {early:?}"
				);
				return;
			}
			let mut edit = super::super::super::config_edit::ConfigDocument::open(path).unwrap();
			edit.upsert_element("listeners", "kind", "smtp", &[("addr", "127.0.0.2".into())])
				.unwrap();
			edit.commit().unwrap();
			drop(held);
			assert!(
				matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
				"the writer escaped the shared lock: {early:?}"
			);
			assert_eq!(
				result
					.recv_timeout(Duration::from_secs(10))
					.unwrap()
					.unwrap(),
				ExitCode::SUCCESS
			);
		});
		assert_eq!(
			Config::load(file.path()).unwrap().listeners[0]
				.addr
				.to_string(),
			"127.0.0.2"
		);
	}
}

/// A generated file that does not parse must leave the configuration as it
/// was: `enable` and `disable` stage both files before replacing either, the
/// same way `set` does.
#[test]
fn enable_and_disable_leave_the_config_alone_when_the_generated_file_is_broken() {
	for bytes in ["{invalid", r#"{"services":{"mail":[]}}"#] {
		for action in [
			ServiceCli::Enable {
				name: ServiceName::Webdav,
			},
			ServiceCli::Disable {
				name: ServiceName::Webdav,
			},
		] {
			let (_dir, file) = fixture();
			let config = Config::load(file.path()).unwrap();
			let compose = super::super::super::init::compose_file_path(&config.data_dir);
			std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
			std::fs::write(&compose, bytes).unwrap();
			let before = std::fs::read(file.path()).unwrap();
			let label = format!("{action:?}");
			let error = execute_with(
				file.path(),
				action,
				false,
				false,
				&mut Vec::new(),
				&mut Vec::new(),
				|_, _| panic!("a refused change must not restart"),
			)
			.unwrap_err();
			assert!(error.to_string().len() > 4, "{error:?}");
			assert_eq!(
				std::fs::read(file.path()).unwrap(),
				before,
				"{label} must not leave the listener in the config"
			);
			assert_eq!(std::fs::read_to_string(compose).unwrap(), bytes);
		}
	}
}

/// A fifo where the generated compose file belongs would turn the listing into
/// a command that waits for a writer that may never come. It has to say which
/// file is in the way instead, and say it inside a second.
#[test]
#[cfg(unix)]
fn a_fifo_at_the_generated_compose_path_stops_the_listing() {
	let (_dir, file) = fixture();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	fifo_at(&compose);
	let (sender, receiver) = std::sync::mpsc::channel();
	let listed = std::thread::spawn(move || {
		let _ = sender.send(list(&config, false, &mut Vec::new()));
	});
	let value = receiver.recv_timeout(std::time::Duration::from_secs(5));
	if value.is_err() {
		drop(std::fs::OpenOptions::new().write(true).open(&compose));
	}
	drop(listed);
	let error = value
		.unwrap_or_else(|_| panic!("service list waited for a fifo writer"))
		.expect_err("a fifo is not a file to read");
	assert!(error.contains("must be a regular file"), "{error}");
	assert!(error.contains(&compose.display().to_string()), "{error}");
}

/// A fifo where `mail.toml` belongs would turn `enable` and `disable` into
/// commands that wait for a writer that may never come, and each one reads the
/// file with the common lock in hand, so the wait would hold the lock with it.
/// Both have to name the file that is in the way instead, inside a few seconds,
/// and leave the lock free for the next writer.
#[test]
#[cfg(unix)]
fn a_fifo_at_the_config_path_stops_enable_and_disable_and_frees_the_lock() {
	// A link is how a fifo gets past a check of the path itself, so it is the
	// case a reader that follows it has to refuse on its own.
	for (linked, refusal) in [
		(false, "config must be a regular file"),
		(true, "is a symlink"),
	] {
		for action in [
			ServiceCli::Enable {
				name: ServiceName::Imap,
			},
			ServiceCli::Disable {
				name: ServiceName::Imap,
			},
		] {
			let dir = tempfile::tempdir_in(".").unwrap();
			let path = dir.path().join("mail.toml");
			let fifo = dir.path().join("mail.toml.fifo");
			fifo_at(&fifo);
			if linked {
				std::os::unix::fs::symlink(&fifo, &path).unwrap();
			} else {
				std::fs::rename(&fifo, &path).unwrap();
			}
			let label = format!(
				"{action:?} on a {} configuration",
				if linked { "linked" } else { "direct" }
			);
			let error = within(&path, &fifo, action).expect_err(&label);
			assert!(error.contains(refusal), "{label}: {error}");
			assert!(
				crate::storage::lock::FileLock::try_acquire(
					&dir.path().join(".epistle-config.lock")
				)
				.unwrap()
				.is_some(),
				"{label} must leave the common lock free"
			);
		}
	}
}
