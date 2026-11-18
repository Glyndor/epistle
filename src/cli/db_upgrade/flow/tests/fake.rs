//! A stack that records what the upgrade asks of it.

use std::path::{Path, PathBuf};

use super::{Change, Outcome, Stack};

pub(super) const OLD: &str = "docker.io/library/postgres:18@sha256:aaaa";
pub(super) const NEW: &str = "docker.io/library/postgres:19@sha256:bbbb";

/// The data directories the two majors report, as `postgres:18` does.
pub(super) const OLD_DIR: &str = "/var/lib/postgresql/18/docker";
pub(super) const NEW_DIR: &str = "/var/lib/postgresql/19/docker";

pub(super) struct Fake {
	pub(super) compose: String,
	pub(super) calls: Vec<String>,
	/// The step that fails, by name (`healthy`) or whole call
	/// (`healthy mail`). Only its first occurrence fails.
	pub(super) fail: Option<&'static str>,
	/// Counts after the restore differ from before.
	pub(super) lossy: bool,
	loaded: bool,
	/// What `SHOW data_directory` answers on each major.
	pub(super) old_dir: String,
	pub(super) new_dir: String,
	/// The status areas that fail on the new major.
	pub(super) failing: Vec<(String, String)>,
	/// The lines reported to the operator, in order.
	pub(super) logged: Vec<String>,
}

impl Fake {
	pub(super) fn new() -> Self {
		Self {
			compose: format!("{{\"services\": {{\"db\": {{\"image\": \"{OLD}\"}}}}}}"),
			calls: Vec::new(),
			fail: None,
			lossy: false,
			loaded: false,
			old_dir: OLD_DIR.to_string(),
			new_dir: NEW_DIR.to_string(),
			failing: Vec::new(),
			logged: Vec::new(),
		}
	}

	fn call(&mut self, name: &'static str, detail: String) -> Result<(), String> {
		let call = format!("{name}{detail}");
		let fails = self.fail == Some(name) || self.fail == Some(call.as_str());
		self.calls.push(call);
		if fails {
			self.fail = None;
			return Err(format!("{name} failed"));
		}
		Ok(())
	}

	/// Whether any of the old cluster, the dump or the image was touched.
	pub(super) fn removed_anything(&self) -> bool {
		// `rm` also starts `rmdir` and `rmdump`.
		self.calls
			.iter()
			.any(|call| call.starts_with("rm") || call.starts_with("images"))
	}

	/// Whether a line reported to the operator contains `text`.
	pub(super) fn said(&self, text: &str) -> bool {
		self.logged.iter().any(|line| line.contains(text))
	}
}

impl Stack for Fake {
	fn compose(&mut self) -> Result<String, String> {
		Ok(self.compose.clone())
	}
	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		let image = if text.contains(NEW) { "19" } else { "18" };
		self.call("write", format!(" {image}"))?;
		self.compose = text.to_string();
		Ok(())
	}
	fn podup(&mut self, args: &[&str]) -> Result<(), String> {
		self.call("podup", format!(" {}", args.join(" ")))
	}
	fn wait_healthy(&mut self, service: &str) -> Result<(), String> {
		self.call("healthy", format!(" {service}"))
	}
	fn counts(&mut self) -> Result<String, String> {
		self.call("counts", String::new())?;
		Ok(if self.loaded && self.lossy {
			"public.accounts=1".into()
		} else {
			"public.accounts=2".into()
		})
	}
	fn dump(&mut self) -> Result<Vec<u8>, String> {
		self.call("dump", String::new())?;
		Ok(b"-- dump".to_vec())
	}
	fn keep_dump(&mut self, name: &str, _: &[u8]) -> Result<PathBuf, String> {
		self.call("keep", format!(" {name}"))?;
		Ok(PathBuf::from(format!("/data/backups/{name}.sql.gz")))
	}
	fn load(&mut self, _: &[u8]) -> Result<(), String> {
		self.call("load", String::new())?;
		self.loaded = true;
		Ok(())
	}
	fn data_directory(&mut self) -> Result<String, String> {
		self.call("datadir", String::new())?;
		Ok(if self.compose.contains(NEW) {
			self.new_dir.clone()
		} else {
			self.old_dir.clone()
		})
	}
	fn failing_checks(&mut self) -> Vec<(String, String)> {
		self.calls.push("checks".to_string());
		self.failing.clone()
	}
	fn remove_in_db(&mut self, path: &str, tree: bool) -> Result<(), String> {
		let name = if tree { "rm" } else { "rmdir" };
		self.call(name, format!(" {path}"))
	}
	fn remove_dump(&mut self, path: &Path) -> Result<(), String> {
		self.call("rmdump", format!(" {}", path.display()))
	}
	fn discard_images(&mut self, change: &Change) -> Result<Outcome, String> {
		self.call("images", format!(" {}", change.retired.join(" ")))?;
		Ok(Outcome {
			removed: change.retired.clone(),
			kept: Vec::new(),
		})
	}
	fn log(&mut self, line: &str) {
		self.logged.push(line.to_string());
	}
}
