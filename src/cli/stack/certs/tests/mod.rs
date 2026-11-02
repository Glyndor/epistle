use super::*;

mod order;

/// A host that records every step and fails the steps it is told to.
#[derive(Default)]
pub(super) struct Recorder {
	pub(super) compose: String,
	pub(super) steps: Vec<String>,
	pub(super) fail_podup_once: bool,
	pub(super) fail_ready: Option<&'static str>,
}

impl Recorder {
	pub(super) fn with_certs(on: bool) -> Self {
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
}

impl SwitchHost for Recorder {
	fn compose_text(&mut self) -> Result<String, String> {
		Ok(self.compose.clone())
	}

	fn render(&mut self, _existing: &str, on: bool) -> Result<String, String> {
		self.steps.push(format!("render {on}"));
		Ok(Recorder::with_certs(on).compose)
	}

	fn place_keys(&mut self, on: bool) -> Result<Vec<String>, String> {
		self.steps.push(format!("place {on}"));
		Ok(Vec::new())
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		let certs = text.contains("certs");
		self.steps.push(format!("write certs={certs}"));
		self.compose = text.to_string();
		Ok(())
	}

	fn podup(&mut self, step: &[&str]) -> Result<(), String> {
		self.steps.push(format!("podup {}", step.join(" ")));
		if self.fail_podup_once {
			self.fail_podup_once = false;
			return Err("podup failed".to_string());
		}
		Ok(())
	}

	fn wait_ready(&mut self, service: &str) -> Result<(), String> {
		self.steps.push(format!("ready {service}"));
		match self.fail_ready {
			Some(failing) if failing == service => {
				self.fail_ready = None;
				Err(format!("{service} did not come up"))
			}
			_ => Ok(()),
		}
	}

	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String> {
		self.steps.push("retire".to_string());
		Ok(None)
	}

	fn log(&mut self, _line: &str) {}
}
