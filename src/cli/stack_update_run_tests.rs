//! Tests for carrying out a `stack update`.

use std::path::PathBuf;

use super::super::{Step, UpdatePlan};
use super::{UpdateHost, execute};

#[derive(Default)]
struct Fake {
	database: bool,
	calls: Vec<String>,
	fail: Option<&'static str>,
}

impl Fake {
	fn call(&mut self, name: &'static str, detail: String) -> Result<(), String> {
		self.calls.push(format!("{name}{detail}"));
		if self.fail == Some(name) {
			return Err(format!("{name} failed"));
		}
		Ok(())
	}
}

impl UpdateHost for Fake {
	fn has_database(&self) -> bool {
		self.database
	}
	fn dump(&mut self) -> Result<Vec<u8>, String> {
		self.call("dump", String::new())?;
		Ok(b"-- sql".to_vec())
	}
	fn keep_dump(&mut self, _: &[u8]) -> Result<PathBuf, String> {
		self.call("keep", String::new())?;
		Ok(PathBuf::from(
			"/data/backups/pre-0.12.0-20261012T000000Z.sql.gz",
		))
	}
	fn write_compose(&mut self, _: &str) -> Result<(), String> {
		self.call("write", String::new())
	}
	fn podup(&mut self, step: &[String]) -> Result<(), String> {
		self.call("podup", format!(" {}", step.join(" ")))
	}
	fn log(&mut self, _: &str) {}
}

fn plan(rewrite: bool) -> UpdatePlan {
	UpdatePlan {
		rewrite: rewrite.then(|| "{}".to_string()),
		diff: Vec::new(),
		notes: Vec::new(),
		steps: vec![
			Step(vec!["up".into(), "-d".into()]),
			Step(vec!["restart".into(), "mail".into()]),
		],
	}
}

#[test]
fn the_database_is_dumped_before_anything_changes() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert_eq!(
		host.calls,
		["dump", "keep", "write", "podup up -d", "podup restart mail"]
	);
}

#[test]
fn a_failed_dump_stops_the_update_before_it_changes_anything() {
	for step in ["dump", "keep"] {
		let mut host = Fake {
			database: true,
			fail: Some(step),
			..Fake::default()
		};
		let error = execute(&mut host, &plan(true)).expect_err(step);
		assert!(error.contains("nothing was changed"), "{step}: {error}");
		assert!(
			!host
				.calls
				.iter()
				.any(|call| call == "write" || call.starts_with("podup")),
			"{step}: {:?}",
			host.calls
		);
	}
}

#[test]
fn a_stack_without_its_own_database_is_not_dumped() {
	let mut host = Fake::default();
	execute(&mut host, &plan(false)).unwrap();
	assert_eq!(host.calls, ["podup up -d", "podup restart mail"]);
}
