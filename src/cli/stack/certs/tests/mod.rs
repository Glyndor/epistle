use super::*;

mod command;
mod failures;
mod lock;
mod order;
mod up;

/// Wait until the stub script at `podup` can be run. A script written a moment
/// ago can still be open for writing in a copy of the descriptor that another
/// test thread's fork holds until its own exec, and the kernel then refuses to
/// run it with `ETXTBSY` ("Text file busy"). Once a run is accepted every such
/// copy is gone, so the test's own runs cannot meet it. The probe's line in the
/// stub's log is removed, so the tests see only their own calls.
fn runnable(podup: &std::path::Path, log: &std::path::Path) {
	for _ in 0..200 {
		match std::process::Command::new(podup).arg("probe").status() {
			Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
				std::thread::sleep(std::time::Duration::from_millis(10));
			}
			_ => break,
		}
	}
	let _ = std::fs::remove_file(log);
}

/// A host that records every step and fails, once each, the steps named in
/// `fail` (`render`, `place`, `write certs=true`, `podup`, `ready mail`...).
pub(super) struct Recorder {
	/// The directory the lock file of the compose file lives in. It is
	/// kept for as long as the host is, so the lock has a home.
	_dir: tempfile::TempDir,
	/// The compose file the switch takes the lock of.
	compose_file: std::path::PathBuf,
	pub(super) compose: String,
	pub(super) steps: Vec<String>,
	pub(super) fail: Vec<&'static str>,
}

impl Recorder {
	pub(super) fn split_layout(on: bool) -> Self {
		let services = if on {
			r#"{"mail": {}, "certs": {}}"#
		} else {
			r#"{"mail": {}}"#
		};
		let dir = tempfile::tempdir().expect("tempdir");
		let compose_file = dir.path().join("compose.yaml");
		Recorder {
			_dir: dir,
			compose_file,
			compose: format!(r#"{{"services": {services}}}"#),
			steps: Vec::new(),
			fail: Vec::new(),
		}
	}

	/// Record `step` and fail it when it is due to fail.
	fn step(&mut self, step: String) -> Result<(), String> {
		let failing = self.fail.iter().position(|name| step.starts_with(name));
		self.steps.push(step.clone());
		match failing {
			Some(index) => {
				self.fail.remove(index);
				Err(step + " failed")
			}
			None => Ok(()),
		}
	}
}

impl SwitchHost for Recorder {
	fn compose_path(&self) -> &std::path::Path {
		&self.compose_file
	}

	fn compose_text(&mut self) -> Result<String, String> {
		Ok(self.compose.clone())
	}

	fn render(&mut self, _existing: &str, on: bool) -> Result<String, String> {
		self.step(format!("render {on}"))?;
		Ok(Recorder::split_layout(on).compose)
	}

	fn place_keys(&mut self, on: bool) -> Result<Vec<String>, String> {
		self.step(format!("place {on}"))?;
		Ok(Vec::new())
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		let certs = text.contains("certs");
		self.step(format!("write certs={certs}"))?;
		self.compose = text.to_string();
		Ok(())
	}

	fn podup(&mut self, step: &[&str]) -> Result<(), String> {
		self.step(format!("podup {}", step.join(" ")))
	}

	fn wait_ready(&mut self, service: &str) -> Result<(), String> {
		self.step(format!("ready {service}"))
	}

	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String> {
		self.step("retire".to_string())?;
		Ok(None)
	}

	fn data_dir_key(&self) -> std::path::PathBuf {
		std::path::PathBuf::from("/data/acme/account.key")
	}

	fn log(&mut self, _line: &str) {}
}
