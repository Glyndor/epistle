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
				action: Some(crate::cli::stack_resources::ResourcesCli::Set {
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
