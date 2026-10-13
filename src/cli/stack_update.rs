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
	/// The changed lines, `-` for removed and `+` for added.
	pub(super) diff: Vec<String>,
	/// How the new file was derived.
	pub(super) notes: Vec<String>,
	/// The podup steps, in order.
	pub(super) steps: Vec<Step>,
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
			line_diff(&existing, &regenerated.text)
		} else {
			Vec::new()
		},
		rewrite: changed.then_some(regenerated.text),
		notes: regenerated.notes,
		steps,
	})
}

/// The lines only `old` has, prefixed `-`, and the lines only `new` has,
/// prefixed `+`, in file order: a longest-common-subsequence diff without
/// context, which is enough for a file of a few hundred lines.
fn line_diff(old: &str, new: &str) -> Vec<String> {
	let old: Vec<&str> = old.lines().collect();
	let new: Vec<&str> = new.lines().collect();
	let mut common = vec![vec![0usize; new.len() + 1]; old.len() + 1];
	for i in (0..old.len()).rev() {
		for j in (0..new.len()).rev() {
			common[i][j] = if old[i] == new[j] {
				common[i + 1][j + 1] + 1
			} else {
				common[i + 1][j].max(common[i][j + 1])
			};
		}
	}
	let (mut i, mut j, mut out) = (0, 0, Vec::new());
	while i < old.len() || j < new.len() {
		if i < old.len() && j < new.len() && old[i] == new[j] {
			i += 1;
			j += 1;
		} else if j < new.len() && (i == old.len() || common[i][j + 1] >= common[i + 1][j]) {
			out.push(format!("+{}", new[j]));
			j += 1;
		} else {
			out.push(format!("-{}", old[i]));
			i += 1;
		}
	}
	out
}

/// Run `stack update`: plan, show and write the new compose file, then run
/// the podup steps.
pub(super) fn run(config: &Config, compose: &Path, podup: &str) -> ExitCode {
	let plan = match plan_update(compose, &config.data_dir, &config.listeners) {
		Ok(plan) => plan,
		Err(error) => {
			super::style::error(format_args!("cannot update {}: {error}", compose.display()));
			return ExitCode::FAILURE;
		}
	};
	let mut err = super::style::stderr();
	for note in &plan.notes {
		let _ = writeln!(err, "epistle: {note}");
	}
	match &plan.rewrite {
		None => {
			let _ = writeln!(err, "epistle: {} is current", compose.display());
		}
		Some(text) => {
			let _ = writeln!(err, "epistle: updating {}:", compose.display());
			for line in &plan.diff {
				let _ = writeln!(err, "  {line}");
			}
			if let Err(error) = crate::storage::write_secret(compose, text.as_bytes()) {
				super::style::error(format_args!("cannot write {}: {error}", compose.display()));
				return ExitCode::FAILURE;
			}
		}
	}
	let argv: Vec<Vec<&str>> = plan
		.steps
		.iter()
		.map(|step| step.0.iter().map(String::as_str).collect())
		.collect();
	let borrowed: Vec<&[&str]> = argv.iter().map(Vec::as_slice).collect();
	super::stack::run_sequence(podup, compose, &borrowed)
}

fn step(parts: &[&str]) -> Step {
	Step(parts.iter().map(|part| part.to_string()).collect())
}

#[cfg(test)]
#[path = "stack_update_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stack_update_steps_tests.rs"]
mod tests_steps;
