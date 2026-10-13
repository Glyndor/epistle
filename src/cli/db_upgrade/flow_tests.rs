//! Tests for the database upgrade, against a fake stack.

use std::path::PathBuf;

use super::{Stack, upgrade};

const OLD: &str = "docker.io/library/postgres:18@sha256:aaaa";
const NEW: &str = "docker.io/library/postgres:19@sha256:bbbb";

#[derive(Default)]
struct Fake {
	compose: String,
	calls: Vec<String>,
	fail: Option<&'static str>,
	/// Counts after the restore differ from before.
	lossy: bool,
	loaded: bool,
}

impl Fake {
	fn new() -> Self {
		Self {
			compose: format!("{{\"services\": {{\"db\": {{\"image\": \"{OLD}\"}}}}}}"),
			..Self::default()
		}
	}
	fn call(&mut self, name: &'static str, detail: String) -> Result<(), String> {
		self.calls.push(format!("{name}{detail}"));
		if self.fail == Some(name) {
			self.fail = None;
			return Err(format!("{name} failed"));
		}
		Ok(())
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
	fn log(&mut self, _: &str) {}
}

#[test]
fn the_data_moves_to_the_new_major_and_the_counts_are_compared() {
	let mut stack = Fake::new();
	let summary = upgrade(&mut stack, NEW).expect("upgrade");
	assert_eq!(
		stack.calls,
		[
			"counts",
			"podup stop mail",
			"dump",
			"keep pre-db-upgrade-18-to-19",
			"podup stop db",
			"write 19",
			"podup up -d db",
			"healthy db",
			"load",
			"counts",
			"podup up -d",
		]
	);
	assert!(stack.compose.contains(NEW));
	assert!(
		summary.contains("/var/lib/postgresql/18"),
		"the operator is told where the old cluster stays: {summary}"
	);
}

#[test]
fn the_same_major_is_left_alone() {
	let mut stack = Fake::new();
	let summary = upgrade(&mut stack, "docker.io/library/postgres:18@sha256:cccc").unwrap();
	assert!(summary.contains("already"), "{summary}");
	assert!(stack.calls.is_empty());
}

#[test]
fn a_downgrade_is_refused() {
	let mut stack = Fake::new();
	let error = upgrade(&mut stack, "docker.io/library/postgres:17@sha256:dddd").unwrap_err();
	assert!(error.contains("17"), "{error}");
	assert!(stack.calls.is_empty());
}

fn fails_back_to_the_old_major(step: &'static str, lossy: bool) {
	let mut stack = Fake::new();
	stack.fail = (!lossy).then_some(step);
	stack.lossy = lossy;
	let error = upgrade(&mut stack, NEW).expect_err("the upgrade fails");
	assert!(
		error.contains("PostgreSQL 18 is running again"),
		"{step}: {error}"
	);
	assert!(
		stack.compose.contains(OLD),
		"{step}: the compose file is back on 18"
	);
	assert_eq!(
		stack.calls.last().map(String::as_str),
		Some("podup up -d"),
		"{step}: the stack, mail included, is started again: {:?}",
		stack.calls
	);
}

#[test]
fn every_failure_after_the_stop_brings_the_old_major_back() {
	for step in ["dump", "keep", "write", "healthy", "load"] {
		fails_back_to_the_old_major(step, false);
	}
	fails_back_to_the_old_major("counts", true);
}
