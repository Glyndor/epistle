//! `stack resources set` and `stack update` both rewrite `compose.yaml`:
//! `set` takes the file's lock and reads it under the lock, so a rewrite
//! that lands while it waits is kept.

use std::process::ExitCode;

use serde_json::Value;

use super::{ResourcesCli, run};

#[test]
fn set_waits_for_the_lock_and_keeps_what_landed_meanwhile() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	let text = crate::cli::init::rendered_for_tests(dir.path(), None);
	std::fs::write(&compose, &text).expect("compose");
	let lock =
		crate::storage::lock::FileLock::acquire(&crate::storage::locked::lock_path(&compose))
			.expect("lock");
	let setting = compose.clone();
	let set = std::thread::spawn(move || {
		let action = Some(ResourcesCli::Set {
			service: "clamav".to_string(),
			memory: Some("2g".to_string()),
			pids: None,
		});
		run(&setting, 25 << 20, action, true, &mut Vec::new())
	});
	std::thread::sleep(std::time::Duration::from_millis(500));
	// What another rewrite (`stack update`) writes while it holds the lock.
	let mut document: Value = serde_json::from_str(&text).expect("json");
	document["x-written-meanwhile"] = Value::Bool(true);
	std::fs::write(&compose, document.to_string()).expect("rewrite");
	drop(lock);
	assert_eq!(set.join().expect("set"), ExitCode::SUCCESS);
	let after: Value =
		serde_json::from_slice(&std::fs::read(&compose).expect("read")).expect("json");
	assert_eq!(
		(
			&after["x-written-meanwhile"],
			&after["services"]["clamav"]["mem_limit"]
		),
		(&Value::Bool(true), &Value::from("2g")),
		"both the rewrite and the new limit are on disk"
	);
}
