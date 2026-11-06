use super::*;

mod failures;
mod order;

/// A host that records every step and fails, once each, the steps named in
/// `fail` (`render`, `place`, `write certs=true`, `podup`, `ready mail`...).
#[derive(Default)]
pub(super) struct Recorder {
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
		Recorder {
			compose: format!(r#"{{"services": {services}}}"#),
			..Recorder::default()
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
