use super::*;
use crate::cli::init::compose_read::fifo_at;
use clap::Parser;
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "private-dns-token";

/// The command's own answer if it comes back inside five seconds. A fifo with
/// no writer releases its reader only when a writer appears, so the deadline is
/// the assertion, and the writer opened afterwards is what lets a run that
/// waited finish instead of holding this thread for the rest of the suite.
/// `config` is where `mail.toml` lives, `fifo` the pipe standing in for the
/// generated file this command reads under the lock.
fn within(config: &Path, fifo: &Path) -> Result<ExitCode, String> {
	use std::sync::mpsc;
	use std::time::Duration;
	let crate::cli::Command::Dns { action, .. } = crate::cli::Cli::try_parse_from([
		"epistle",
		"dns",
		"provider",
		"set",
		"desec",
		"--zone",
		"example.org",
		"--store-token",
	])
	.unwrap()
	.command
	else {
		unreachable!()
	};
	let (sender, receiver) = mpsc::channel();
	let reading = config.to_path_buf();
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
					|_, _| panic!("a refused generated file must not reach the stack"),
				)
				.map_err(|error| error.to_string()),
			)
			.ok();
	});
	let value = receiver.recv_timeout(Duration::from_secs(5));
	if value.is_err() {
		drop(std::fs::OpenOptions::new().write(true).open(&release));
	}
	let result = value.unwrap_or_else(|_| {
		panic!(
			"dns provider set waited for a writer of {} that never came",
			release.display()
		)
	});
	running.join().expect("the command thread panicked");
	result
}

/// A fifo where the generated compose file belongs would turn `dns provider set
/// --store-token` into a command that waits for a writer that may never come,
/// and it reads that file with the common lock in hand, so the wait would hold
/// the lock with it. Both shapes have to be refused with the path in the
/// message, the token has to stay where it was, and the lock has to come back.
#[test]
fn a_fifo_at_the_generated_compose_path_stops_the_token_migration_and_frees_the_lock() {
	for linked in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let data = dir.path().join("data");
		std::fs::create_dir(&data).unwrap();
		let path = dir.path().join("mail.toml");
		std::fs::write(
			&path,
			format!(
				"hostname = 'mail.example.org'\ndata_dir = {data:?}\n[dns]\nprovider = 'desec'\nzone = 'example.org'\ntoken = '{TOKEN}'\n"
			),
		)
		.unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		let compose = crate::cli::init::compose_file_path(&data);
		std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
		let fifo = dir.path().join("compose.fifo");
		fifo_at(&fifo);
		if linked {
			std::os::unix::fs::symlink(&fifo, &compose).unwrap();
		} else {
			std::fs::rename(&fifo, &compose).unwrap();
		}
		let label = format!("a {} fifo", if linked { "linked" } else { "direct" });
		let error = within(&path, &fifo).expect_err(&label);
		assert!(error.contains("must be a regular file"), "{label}: {error}");
		assert!(
			error.contains(&compose.display().to_string()),
			"{label}: {error}"
		);
		assert!(
			!dir.path().join("secrets/dns_provider_token").exists(),
			"{label}: the token it could not mount must not be stored"
		);
		assert!(
			crate::storage::lock::FileLock::try_acquire(&dir.path().join(".epistle-config.lock"))
				.unwrap()
				.is_some(),
			"{label}: the common lock must come back"
		);
	}
}

fn migrate(source: &str, dry_run: bool, stack: bool) {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().join("data");
	std::fs::create_dir(&data).unwrap();
	let path = dir.path().join("mail.toml");
	let original = format!(
		"hostname = 'mail.example.org'\ndata_dir = {data:?}\n[dns]\nprovider = 'desec'\nzone = 'example.org'\n{source}\n"
	);
	std::fs::write(&path, &original).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let compose = crate::cli::init::compose_file_path(&data);
	if stack {
		std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
		std::fs::write(&compose, r#"{"services":{"mail":{"environment":{"DNS_MIGRATION_TEST_TOKEN":"${DNS_MIGRATION_TEST_TOKEN}","TZ":"UTC"},"volumes":[]},"db":{"environment":{}}}}"#).unwrap();
	}
	let crate::cli::Command::Dns { action, .. } = crate::cli::Cli::try_parse_from([
		"epistle",
		"dns",
		"provider",
		"set",
		"desec",
		"--zone",
		"example.org",
		"--store-token",
	])
	.unwrap()
	.command
	else {
		unreachable!()
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action,
		dry_run,
		false,
		&mut out,
		&mut status,
		|_, action| {
			assert!(matches!(action, StackAction::Recreate { service } if service == "mail"));
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert!(!String::from_utf8(out).unwrap().contains(TOKEN));
	assert!(!String::from_utf8(status).unwrap().contains(TOKEN));
	let secret = dir.path().join("secrets/dns_provider_token");
	if dry_run {
		assert!(!secret.exists());
		assert_eq!(std::fs::read_to_string(path).unwrap(), original);
		return;
	}
	assert!(std::fs::read_to_string(&secret).unwrap() == TOKEN);
	assert_eq!(
		std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
		0o600
	);
	let config = Config::load(&path).unwrap();
	let dns = config.dns.unwrap();
	assert_eq!(dns.token_file.as_ref(), Some(&secret));
	assert!(dns.token.is_none() && dns.token_env.is_none());
	assert!(dns.build().is_some());
	if stack {
		let rendered = std::fs::read_to_string(compose).unwrap();
		assert!(!rendered.contains(TOKEN));
		let compose: serde_json::Value = serde_json::from_str(&rendered).unwrap();
		assert!(
			compose["services"]["mail"]["environment"]
				.get("DNS_MIGRATION_TEST_TOKEN")
				.is_none()
		);
		assert!(
			compose["services"]["mail"]["volumes"]
				.as_array()
				.unwrap()
				.iter()
				.any(|mount| mount["source"] == secret.display().to_string()
					&& mount["read_only"] == true)
		);
		assert!(compose["services"]["db"].get("volumes").is_none());
	}
	std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
	let error = crate::dns::provider::ScopedSecret::from_file("example.org", &secret).unwrap_err();
	assert!(error.to_string().contains("0600"));
	assert!(!error.to_string().contains(TOKEN));
	assert!(dns.build().is_none());
}

#[test]
fn store_inline_token_and_preview_without_disclosure() {
	migrate("token = 'private-dns-token'", true, false);
	migrate("token = 'private-dns-token'", false, false);
}

#[test]
fn store_environment_token_and_remove_container_environment() {
	unsafe { std::env::set_var("DNS_MIGRATION_TEST_TOKEN", TOKEN) };
	migrate("token_env = 'DNS_MIGRATION_TEST_TOKEN'", false, true);
}

/// `dns provider set` writes `mail.toml` and the generated compose file, so
/// it waits for the common lock like every other writer of them, and it reads
/// the configuration only after it has the lock. A command that edits the file
/// in the meantime must not be overwritten by a compose rollback.
#[test]
fn the_token_migration_waits_for_the_common_lock_and_reads_the_latest_config() {
	use std::sync::mpsc;
	use std::time::Duration;
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().join("data");
	std::fs::create_dir(&data).unwrap();
	let path = dir.path().join("mail.toml");
	let original = format!(
		"hostname = 'mail.example.org'\ndata_dir = {data:?}\n[dns]\nprovider = 'desec'\nzone = 'example.org'\ntoken = '{TOKEN}'\n"
	);
	std::fs::write(&path, &original).unwrap();
	let compose = crate::cli::init::compose_file_path(&data);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"environment":{},"volumes":[]}}}"#,
	)
	.unwrap();
	let action = || {
		let crate::cli::Command::Dns { action, .. } = crate::cli::Cli::try_parse_from([
			"epistle",
			"dns",
			"provider",
			"set",
			"desec",
			"--zone",
			"example.org",
			"--store-token",
		])
		.unwrap()
		.command
		else {
			unreachable!()
		};
		action
	};
	let held = crate::cli::service_lock::acquire(&path).unwrap();
	std::thread::scope(|scope| {
		let (started, starting) = mpsc::channel();
		let (done, result) = mpsc::channel();
		let config = &path;
		scope.spawn(move || {
			started.send(()).unwrap();
			let code = execute_with(
				config,
				action(),
				false,
				false,
				&mut Vec::new(),
				&mut Vec::new(),
				|_, _| ExitCode::SUCCESS,
			);
			done.send(code).unwrap();
		});
		starting.recv().unwrap();
		assert!(
			matches!(
				result.recv_timeout(Duration::from_millis(200)),
				Err(mpsc::RecvTimeoutError::Timeout)
			),
			"the command escaped the shared lock"
		);
		// This edit has to be the one the command reads: without the lock it
		// would load the file before this write and its rollback would put
		// the compose file it read back over this one.
		let edited = format!("{original}\n# edited by another command\n");
		std::fs::write(config, &edited).unwrap();
		std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o600)).unwrap();
		drop(held);
		assert_eq!(
			result
				.recv_timeout(Duration::from_secs(10))
				.unwrap()
				.unwrap(),
			ExitCode::SUCCESS
		);
		let left = std::fs::read_to_string(&path).unwrap();
		assert!(
			left.contains("# edited by another command") && left.contains("token_file"),
			"the command must keep the other command's edit: {left}"
		);
		let compose = std::fs::read_to_string(&compose).unwrap();
		assert!(
			!compose.contains("DNS_MIGRATION_TEST_TOKEN"),
			"the mount is added once: {compose}"
		);
		let secret = dir.path().join("secrets/dns_provider_token");
		let document: serde_json::Value = serde_json::from_str(&compose).unwrap();
		assert!(
			document["services"]["mail"]["volumes"]
				.as_array()
				.unwrap()
				.iter()
				.any(|mount| mount["source"] == secret.display().to_string()),
			"the mount that carries the token has to reach the generated file: {compose}"
		);
	});
}
