//! Tests for carrying out a `stack update`.

use std::path::PathBuf;

use super::super::super::{Step, UpdatePlan};
use super::{UpdateHost, execute};
use crate::cli::stack::images::{Change, Outcome};

#[derive(Default)]
struct Fake {
	database: bool,
	/// Whether the compose file runs the certificates container.
	certs: bool,
	calls: Vec<String>,
	fail: Option<&'static str>,
	/// Areas `status` reports failing after the restart.
	failing: Vec<(String, String)>,
	/// The areas the update judged after the restart.
	judged: Vec<crate::cli::status::CheckArea>,
	logged: Vec<String>,
	/// Whether the harden step finds a superuser to take apart.
	superuser: bool,
	/// What the update asked `prepare_keys` for, as to the panel.
	panel_asked: Option<bool>,
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
	fn discard_images(&mut self, change: &Change) -> Result<Outcome, String> {
		self.call("images", format!(" {}", change.retired.join(",")))?;
		Ok(Outcome {
			removed: vec!["docker.io/clamav/clamav:1.5@sha256:old".to_string()],
			kept: vec!["ghcr.io/glyndor/epistle:0.12.5: a container still uses it".to_string()],
		})
	}
	fn harden_database(&mut self) -> Result<bool, String> {
		self.call("harden", String::new())?;
		Ok(self.superuser)
	}
	fn prepare_keys(&mut self, panel: bool) -> Result<Vec<String>, String> {
		self.panel_asked = Some(panel);
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
	fn runs_certs(&self) -> bool {
		self.certs
	}
	fn wait_steady(&mut self, service: &str) -> Result<(), String> {
		self.calls.push(format!("steady {service}"));
		if self.fail == Some("steady") {
			return Err(format!("the {service} container did not stay up"));
		}
		Ok(())
	}
	fn failing_areas(&mut self, areas: &[crate::cli::status::CheckArea]) -> Vec<(String, String)> {
		self.calls.push("status".into());
		self.judged = areas.to_vec();
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
		panel: false,
		images: Change {
			retired: vec!["ghcr.io/glyndor/epistle:0.12.5".to_string()],
			current: vec!["gcr.io/distroless/static-debian13:nonroot@sha256:new".to_string()],
		},
	}
}

mod dumps;
mod images;
mod steps;
