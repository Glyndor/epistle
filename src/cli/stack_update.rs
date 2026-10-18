//! `epistle stack update`: bring the stack to what this release's code
//! renders, then restart what needs it.
//!
//! The compose file is rendered again from the existing one and the config
//! (see `init::regenerate`), so a release that adds a service, a secret, a
//! digest or a hardening option reaches installs that ran `epistle init`
//! with an older release. The difference is shown, the file is replaced
//! atomically, and `podup up -d` recreates only the services whose
//! definition changed. The default `mail` service runs the host's
//! `/usr/bin/epistle`, which the package just replaced, so it is restarted
//! when `up` did not already recreate it. A custom `mail` image is the
//! operator's: it is pulled before `up`.
//!
//! The legacy `rewrite_default_image` helper lived here; the logic it
//! carried (rewriting a managed image to the build-time CLI version) no
//! longer exists because the default image is the unchanging distroless
//! base.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;

use crate::config::{Config, Listener};

/// One podup invocation: the arguments after `podup -f <compose>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Step(pub Vec<String>);

/// What `stack update` will do.
#[derive(Debug)]
pub(super) struct UpdatePlan {
	/// The new compose file, when it differs from the one on disk.
	pub(super) rewrite: Option<String>,
	/// What changed, one line per value under its service name.
	pub(super) diff: Vec<String>,
	/// How the new file was derived.
	pub(super) notes: Vec<String>,
	/// The podup steps, in order.
	pub(super) steps: Vec<Step>,
	/// The config path the `mail` service serves, which `status` reads.
	pub(super) config_path: std::path::PathBuf,
}

/// Read the compose file at `compose`, render it again for an install
/// whose config has `data_dir` and `listeners`, and decide the podup steps.
/// `Err` names what could not be read or understood; nothing is written.
pub(super) fn plan_update(
	compose: &Path,
	data_dir: &Path,
	listeners: &[Listener],
) -> Result<UpdatePlan, String> {
	let existing = std::fs::read_to_string(compose)
		.map_err(|error| format!("cannot read {}: {error}", compose.display()))?;
	let regenerated = crate::cli::init::regenerate(data_dir, listeners, &existing)?;
	let old: Value = serde_json::from_str(&existing).map_err(|error| error.to_string())?;
	let new: Value = serde_json::from_str(&regenerated.text).map_err(|error| error.to_string())?;
	let managed = new
		.get("x-epistle-managed-image")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	let steps = if !managed {
		vec![step(&["pull"]), step(&["up", "-d"])]
	} else if old["services"]["mail"] == new["services"]["mail"] {
		vec![step(&["up", "-d"]), step(&["restart", "mail"])]
	} else {
		vec![step(&["up", "-d"])]
	};
	let changed = regenerated.text != existing;
	Ok(UpdatePlan {
		diff: if changed {
			compose_diff(&old, &new)
		} else {
			Vec::new()
		},
		rewrite: changed.then_some(regenerated.text),
		notes: regenerated.notes,
		steps,
		config_path: regenerated.config_path,
	})
}

/// What changed between two compose documents, one line per changed value
/// under the service it belongs to (`clamav: image "a" -> "b"`), plus
/// `<service>: added` / `removed`. Objects are walked; arrays and scalars
/// are compared whole.
pub(super) fn compose_diff(old: &Value, new: &Value) -> Vec<String> {
	let mut lines = Vec::new();
	let services = |value: &Value| value["services"].as_object().cloned().unwrap_or_default();
	let (old_services, new_services) = (services(old), services(new));
	let mut names: Vec<&String> = old_services.keys().chain(new_services.keys()).collect();
	names.sort();
	names.dedup();
	for name in names {
		match (old_services.get(name), new_services.get(name)) {
			(None, Some(_)) => lines.push(format!("{name}: added")),
			(Some(_), None) => lines.push(format!("{name}: removed")),
			(Some(before), Some(after)) => {
				for change in changes("", before, after) {
					lines.push(format!("{name}: {change}"));
				}
			}
			(None, None) => {}
		}
	}
	let rest = |value: &Value| {
		let mut map = value.as_object().cloned().unwrap_or_default();
		map.remove("services");
		Value::Object(map)
	};
	for change in changes("", &rest(old), &rest(new)) {
		// `volumes.b added {}` reads as `volumes.b: added {}`.
		lines.push(change.replacen(' ', ": ", 1));
	}
	lines
}

/// The changed leaves under `path`, as `<path> <old> -> <new>`,
/// `<path> added <new>` or `<path> removed (was <old>)`.
fn changes(path: &str, old: &Value, new: &Value) -> Vec<String> {
	let join = |key: &str| {
		if path.is_empty() {
			key.to_string()
		} else {
			format!("{path}.{key}")
		}
	};
	match (old, new) {
		(Value::Object(before), Value::Object(after)) => {
			let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
			keys.sort();
			keys.dedup();
			keys.into_iter()
				.flat_map(|key| match (before.get(key), after.get(key)) {
					(Some(a), Some(b)) => changes(&join(key), a, b),
					(None, Some(b)) => vec![format!("{} added {b}", join(key))],
					(Some(a), None) => vec![format!("{} removed (was {a})", join(key))],
					(None, None) => Vec::new(),
				})
				.collect()
		}
		(a, b) if a == b => Vec::new(),
		(a, b) => vec![format!("{path} {a} -> {b}")],
	}
}

/// Run `stack update`: plan, dump the database, write the new compose
/// file and run the podup steps.
pub(super) fn run(config: &Config, compose: &Path, podup: &str) -> ExitCode {
	// `stack resources set` rewrites the same file under the same lock. It
	// is held from the read to the last step, so a limit set meanwhile is
	// neither lost under the new file nor written over the update.
	let lock = crate::storage::locked::lock_path(compose);
	let _held = match crate::storage::lock::FileLock::acquire(&lock) {
		Ok(held) => held,
		Err(error) => {
			super::style::error(format_args!("cannot lock {}: {error}", lock.display()));
			return ExitCode::FAILURE;
		}
	};
	let plan = match plan_update(compose, &config.data_dir, &config.listeners) {
		Ok(plan) => plan,
		Err(error) => {
			super::style::error(format_args!("cannot update {}: {error}", compose.display()));
			return ExitCode::FAILURE;
		}
	};
	// The socket unit can be listening while `podman system service` is
	// still starting, as it is right after an upgrade or a boot. Nothing has
	// changed yet, so a service that never answers stops the update here.
	if !super::stack_retry::wait_for_api(
		&super::stack_socket::socket_path(),
		super::stack_retry::API_WAIT,
	) {
		super::style::error(format_args!(
			"Podman's API at {} did not answer within {} s; nothing was changed",
			super::stack_socket::socket_path().display(),
			super::stack_retry::API_WAIT.as_secs()
		));
		return ExitCode::FAILURE;
	}
	let mut host = Live {
		config,
		compose,
		podup,
		database: plan_has_database(compose),
		config_path: &plan.config_path,
	};
	match execute::execute(&mut host, &plan) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(format_args!("stack update failed: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// How long `mail` may take to report healthy after the restart: its
/// healthcheck starts after 30 s and runs every 30 s, so this leaves room
/// for several failed probes before the update is called failed.
const HEALTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The `status` areas a restart can break. DNS, TLS, the queue and the
/// antivirus depend on the world outside the restart (a recreated clamav
/// spends minutes downloading signatures), so they do not judge it.
const RESTART_AREAS: [super::status::CheckArea; 3] = [
	super::status::CheckArea::Config,
	super::status::CheckArea::Ports,
	super::status::CheckArea::Db,
];

/// Whether the compose file on disk has a `db` service.
fn plan_has_database(compose: &Path) -> bool {
	std::fs::read(compose)
		.ok()
		.and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
		.is_some_and(|value| value["services"].get("db").is_some())
}

/// The real host of an update: podup, the backup code's dump, stderr.
struct Live<'a> {
	config: &'a Config,
	compose: &'a Path,
	podup: &'a str,
	database: bool,
	config_path: &'a Path,
}

impl execute::UpdateHost for Live<'_> {
	fn has_database(&self) -> bool {
		self.database && self.config.database.is_some()
	}

	fn dump(&mut self) -> Result<Vec<u8>, String> {
		let database = self
			.config
			.database
			.as_ref()
			.ok_or("the config has no [database]")?;
		super::backup::collect_dump(database, &self.config.data_dir)
			.map_err(|error| error.to_string())
	}

	fn keep_dump(&mut self, sql: &[u8]) -> Result<std::path::PathBuf, String> {
		let name = format!("pre-{}", env!("CARGO_PKG_VERSION"));
		super::stack_dumps::keep(
			&self.config.data_dir,
			&name,
			sql,
			std::time::SystemTime::now(),
		)
		.map_err(|error| error.to_string())
	}

	fn harden_database(&mut self) -> Result<bool, String> {
		super::db_harden::run(self.compose)
	}

	fn prepare_keys(&mut self) -> Result<Vec<String>, String> {
		crate::cli::init::prepare_keys_for_update(
			&self.config.data_dir,
			self.config_path,
			self.has_database(),
		)
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		crate::storage::write_secret(self.compose, text.as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", self.compose.display()))
	}

	fn podup(&mut self, step: &[String]) -> Result<(), String> {
		let args: Vec<&str> = step.iter().map(String::as_str).collect();
		let label = format!("`podup {}`", args.join(" "));
		super::stack_retry::with_retries(
			|| {
				super::stack_retry::run_tee(super::stack::build_command(
					self.podup,
					self.compose,
					&args,
				))
			},
			|| {
				super::stack_retry::wait_for_api(
					&super::stack_socket::socket_path(),
					super::stack_retry::API_WAIT,
				)
			},
			|line| {
				let _ = writeln!(super::style::stderr(), "epistle: {line}");
			},
		)
		.map_err(|error| format!("{label} failed: {error}"))
	}

	fn wait_healthy(&mut self, service: &str) -> Result<(), String> {
		super::stack_health::wait_healthy(self.podup, self.compose, service, HEALTH_TIMEOUT)
	}

	fn failing_areas(&mut self) -> Vec<(String, String)> {
		super::status::failing(self.config_path, &RESTART_AREAS)
			.unwrap_or_else(|error| vec![("status".to_string(), error)])
	}

	fn log(&mut self, line: &str) {
		let _ = writeln!(super::style::stderr(), "epistle: {line}");
	}
}

fn step(parts: &[&str]) -> Step {
	Step(parts.iter().map(|part| part.to_string()).collect())
}

#[path = "stack_update_run.rs"]
mod execute;

#[cfg(test)]
#[path = "stack_update_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stack_update_steps_tests.rs"]
mod tests_steps;
