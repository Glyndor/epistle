//! The switch rewrites the compose file under the lock that guards it, the
//! same one `stack update`, `stack resources set` and `dns provider set`
//! take: a rewrite that lands while the switch waits for the lock is read
//! again under it and not lost.

use super::*;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A host that reads and writes a real compose file, the way the command
/// does, and records the steps it took.
struct FileHost {
	/// The compose file the switch rewrites.
	compose: PathBuf,
	/// The data directory of the install the file belongs to.
	data_dir: PathBuf,
	/// The steps the switch took, so a test can see that it took none.
	steps: Arc<Mutex<Vec<String>>>,
}

impl FileHost {
	/// A host over the compose file of an install whose `data_dir` is
	/// `data_dir`, with the file `epistle init` writes in it.
	fn new(data_dir: &Path, compose: PathBuf) -> Self {
		std::fs::write(
			&compose,
			crate::cli::init::rendered_for_tests(data_dir, None),
		)
		.expect("compose");
		FileHost {
			compose,
			data_dir: data_dir.to_path_buf(),
			steps: Arc::new(Mutex::new(Vec::new())),
		}
	}
}

impl SwitchHost for FileHost {
	fn compose_path(&self) -> &Path {
		&self.compose
	}

	fn compose_text(&mut self) -> Result<String, String> {
		self.steps.lock().expect("steps").push("read".to_string());
		let bytes = std::fs::read(&self.compose)
			.map_err(|error| format!("cannot read {}: {error}", self.compose.display()))?;
		String::from_utf8(bytes)
			.map_err(|_| format!("{} is not valid UTF-8", self.compose.display()))
	}

	fn render(&mut self, existing: &str, on: bool) -> Result<String, String> {
		self.steps
			.lock()
			.expect("steps")
			.push(format!("render {on}"));
		crate::cli::init::regenerate_with(&self.data_dir, &[], existing, Some(on))
			.map(|regenerated| regenerated.text)
	}

	fn place_keys(&mut self, on: bool) -> Result<Vec<String>, String> {
		self.steps
			.lock()
			.expect("steps")
			.push(format!("place {on}"));
		Ok(Vec::new())
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		self.steps.lock().expect("steps").push("write".to_string());
		crate::storage::write_secret(&self.compose, text.as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", self.compose.display()))
	}

	fn podup(&mut self, step: &[&str]) -> Result<(), String> {
		self.steps
			.lock()
			.expect("steps")
			.push(format!("podup {}", step.join(" ")));
		Ok(())
	}

	fn wait_ready(&mut self, service: &str) -> Result<(), String> {
		self.steps
			.lock()
			.expect("steps")
			.push(format!("ready {service}"));
		Ok(())
	}

	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String> {
		self.steps.lock().expect("steps").push("retire".to_string());
		Ok(None)
	}

	fn data_dir_key(&self) -> PathBuf {
		PathBuf::from("/data/acme/account.key")
	}

	fn log(&mut self, _line: &str) {}
}

/// The switch waits for the lock that guards the compose file: while
/// another holder has it, the switch does not even read the file, so it
/// cannot write a render of a file that is about to change.
#[test]
fn the_switch_waits_for_the_lock_before_it_reads_the_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let compose = dir.path().join("compose.yaml");
	let host = FileHost::new(&data_dir, compose.clone());
	let steps = host.steps.clone();
	let held =
		crate::storage::lock::FileLock::acquire(&crate::storage::locked::lock_path(&compose))
			.expect("lock");
	let running = std::thread::spawn(move || {
		let mut host = host;
		switch(&mut host, true)
	});
	std::thread::sleep(Duration::from_millis(500));
	assert!(
		steps.lock().expect("steps").is_empty(),
		"the switch went ahead while the lock was held elsewhere"
	);
	drop(held);
	assert_eq!(running.join().expect("switch"), Ok(Switched::Done));
	assert!(
		!steps.lock().expect("steps").is_empty(),
		"the switch did nothing at all"
	);
}

/// A rewrite that lands while the switch waits for the lock is not lost:
/// the file is read again under the lock, so the render is made of what
/// the rewrite left and both changes are on disk.
#[test]
fn a_rewrite_that_lands_while_the_switch_waits_is_not_lost() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let compose = dir.path().join("compose.yaml");
	let host = FileHost::new(&data_dir, compose.clone());
	let held =
		crate::storage::lock::FileLock::acquire(&crate::storage::locked::lock_path(&compose))
			.expect("lock");
	let running = std::thread::spawn(move || {
		let mut host = host;
		switch(&mut host, true)
	});
	std::thread::sleep(Duration::from_millis(500));
	// What another writer of the file leaves while it holds the lock: the
	// memory limit `stack resources set` records, which the render of the
	// file keeps.
	let mut document: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&compose).expect("read")).expect("json");
	document["x-epistle-resources"] = serde_json::json!({"mail": {"memory": "2g"}});
	std::fs::write(&compose, document.to_string()).expect("rewrite");
	drop(held);
	assert_eq!(running.join().expect("switch"), Ok(Switched::Done));
	let after: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&compose).expect("read")).expect("json");
	assert!(
		after["services"].get("certs").is_some(),
		"the switch did not write its own change: {after}"
	);
	assert_eq!(
		after["services"]["mail"]["mem_limit"], "2g",
		"the rewrite that landed meanwhile was overwritten: {after}"
	);
}
