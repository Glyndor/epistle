//! Tests for carrying out a `stack update`.

use std::path::PathBuf;

use super::super::super::{Step, UpdatePlan};
use super::{UpdateHost, execute};

#[derive(Default)]
struct Fake {
	database: bool,
	calls: Vec<String>,
	fail: Option<&'static str>,
	/// Areas `status` reports failing after the restart.
	failing: Vec<(String, String)>,
	logged: Vec<String>,
	/// Whether the harden step finds a superuser to take apart.
	superuser: bool,
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
	fn discard_dumps(&mut self) -> Result<usize, String> {
		self.call("discard", String::new())?;
		Ok(1)
	}
	fn harden_database(&mut self) -> Result<bool, String> {
		self.call("harden", String::new())?;
		Ok(self.superuser)
	}
	fn prepare_keys(&mut self) -> Result<Vec<String>, String> {
		self.call("keys", String::new())?;
		Ok(vec!["moved a key".to_string()])
	}
	fn write_compose(&mut self, _: &str) -> Result<(), String> {
		self.call("write", String::new())
	}
	fn podup(&mut self, step: &[String]) -> Result<(), String> {
		self.call("podup", format!(" {}", step.join(" ")))
	}
	fn wait_healthy(&mut self, service: &str) -> Result<(), String> {
		self.call("healthy", format!(" {service}"))
	}
	fn failing_areas(&mut self) -> Vec<(String, String)> {
		self.calls.push("status".into());
		self.failing.clone()
	}
	fn log(&mut self, line: &str) {
		self.logged.push(line.to_string());
	}
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
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
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
		[
			"dump",
			"keep",
			"keys",
			"write",
			"podup up -d",
			"podup restart mail",
			"harden",
			"healthy mail",
			"status",
			"discard"
		]
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
	assert_eq!(
		host.calls,
		[
			"keys",
			"podup up -d",
			"podup restart mail",
			"healthy mail",
			"status"
		]
	);
}

#[test]
fn the_dumps_go_only_once_the_update_is_verified() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	let at = |name: &str| host.calls.iter().position(|call| call == name).unwrap();
	assert!(
		at("healthy mail") < at("status") && at("status") < at("discard"),
		"{:?}",
		host.calls
	);
	assert!(
		host.logged
			.iter()
			.any(|line| line.contains("removed 1 dump(s)")),
		"{:?}",
		host.logged
	);
}

#[test]
fn an_update_that_does_not_verify_keeps_its_dumps() {
	for (fail, failing) in [
		(Some("healthy"), Vec::new()),
		(None, vec![("db".to_string(), "refused".to_string())]),
		(Some("harden"), Vec::new()),
		(Some("podup"), Vec::new()),
	] {
		let mut host = Fake {
			database: true,
			fail,
			failing,
			..Fake::default()
		};
		execute(&mut host, &plan(true)).expect_err("the update fails");
		assert!(
			!host.calls.iter().any(|call| call == "discard"),
			"{fail:?}: {:?}",
			host.calls
		);
	}
}

#[test]
fn a_stack_without_a_database_has_no_dumps_to_remove() {
	let mut host = Fake::default();
	execute(&mut host, &plan(false)).unwrap();
	assert!(!host.calls.iter().any(|call| call == "discard"));
}

#[test]
fn dumps_that_cannot_be_removed_do_not_fail_a_verified_update() {
	let mut host = Fake {
		database: true,
		fail: Some("discard"),
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert!(
		host.logged
			.iter()
			.any(|line| line.contains("could not remove the dumps")),
		"{:?}",
		host.logged
	);
}

#[test]
fn an_unhealthy_mail_names_the_rollback() {
	let mut host = Fake {
		fail: Some("healthy"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(false)).expect_err("mail never got healthy");
	assert!(
		error.contains("healthy failed") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
}

#[test]
fn a_failing_status_area_is_named_with_the_rollback() {
	let mut host = Fake {
		failing: vec![("db".into(), "connection refused".into())],
		..Fake::default()
	};
	let error = execute(&mut host, &plan(false)).expect_err("db fails after the restart");
	assert!(
		error.contains("db: connection refused") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
}

#[test]
fn the_keys_move_out_of_data_dir_before_the_compose_file_names_them() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	let at = |name: &str| host.calls.iter().position(|call| call == name).unwrap();
	assert!(
		at("keep") < at("keys") && at("keys") < at("write"),
		"{:?}",
		host.calls
	);
	assert!(
		host.logged.iter().any(|line| line == "moved a key"),
		"{:?}",
		host.logged
	);
}

#[test]
fn a_key_that_cannot_move_stops_the_update_before_the_compose_file_changes() {
	let mut host = Fake {
		database: true,
		fail: Some("keys"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(true)).expect_err("keys");
	assert!(error.contains("keys failed"), "{error}");
	assert!(
		!host
			.calls
			.iter()
			.any(|call| call == "write" || call.starts_with("podup")),
		"{:?}",
		host.calls
	);
}

#[test]
fn an_epistle_superuser_is_taken_apart_and_mail_reconnects() {
	let mut host = Fake {
		database: true,
		superuser: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert_eq!(
		host.calls[host.calls.len() - 6..],
		[
			"podup restart mail",
			"harden",
			"podup restart mail",
			"healthy mail",
			"status",
			"discard"
		],
		"mail's pooled sessions still carry the renamed superuser until it restarts"
	);
}

#[test]
fn a_failed_harden_names_the_rollback() {
	let mut host = Fake {
		database: true,
		fail: Some("harden"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(true)).expect_err("harden");
	assert!(
		error.contains("harden failed") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
	assert!(!host.calls.iter().any(|call| call.starts_with("healthy")));
}
