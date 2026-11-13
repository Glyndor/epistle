//! What each kind of step does: plan it, decide its value, tell whether that
//! value is in place, and put it there.

mod config;
mod credentials;
mod dkim;

use std::path::Path;

use crate::config::Config;

use super::journal::{Intent, Kind, Step};
use super::secrets::Secrets;

/// What every step needs from the run.
pub(in crate::cli::rotate) struct Context<'a> {
	/// The configuration file, which some steps edit.
	pub path: &'a Path,
	/// The configuration as loaded when the run began.
	pub config: &'a Config,
	/// The time of this run, epoch seconds.
	pub now: u64,
}

/// Every step of a new run in order, and the notes for what this server
/// cannot rotate. Checks what the steps will check, so a refusal comes
/// before anything is changed. A restart closes the run when a step edits
/// the configuration.
pub(in crate::cli::rotate) fn plan(context: &Context) -> Result<(Vec<Step>, Vec<String>), String> {
	let mut steps = credentials::plan(context.config)?;
	let (in_file, mut notes) = config::plan(context.path, context.config)?;
	let edits_file = !in_file.is_empty();
	steps.extend(in_file);
	let (keys, key_notes) = dkim::plan(context.config, context.now)?;
	steps.extend(keys);
	notes.extend(key_notes);
	if edits_file {
		steps.push(Step::pending(Kind::Restart, "", None));
	}
	Ok((steps, notes))
}

/// Decide the value the step leaves, keeping any new secret first.
pub(in crate::cli::rotate) fn prepare(
	context: &Context,
	step: &Step,
	secrets: &mut Secrets,
) -> Result<Intent, String> {
	match step.kind {
		Kind::ApiKey | Kind::AppPassword => credentials::prepare(context.config, step, secrets),
		Kind::WebhookSecret | Kind::SrsSecret => config::prepare(context.path, step, secrets),
		Kind::DkimKey | Kind::DkimDomainKey => dkim::prepare(context.config, step),
		Kind::Restart => Ok(Intent::Again),
	}
}

/// Whether the value the step decided on is already in place.
pub(in crate::cli::rotate) fn landed(
	context: &Context,
	step: &Step,
	intent: &Intent,
) -> Result<bool, String> {
	match (step.kind, intent) {
		(Kind::ApiKey | Kind::AppPassword, Intent::Replace { new, .. }) => {
			credentials::landed(context.config, step, new)
		}
		(Kind::WebhookSecret | Kind::SrsSecret, Intent::Replace { new, .. }) => {
			config::landed(context.path, step, new)
		}
		(Kind::DkimKey | Kind::DkimDomainKey, Intent::Queued { active }) => {
			dkim::landed(context.config, step, active)
		}
		(_, Intent::Again) => Ok(false),
		_ => Err(format!(
			"the journal records a {intent:?} for a {:?} step",
			step.kind
		)),
	}
}

/// Put the decided value in place. The restart is the caller's.
pub(in crate::cli::rotate) fn apply(
	context: &Context,
	step: &Step,
	intent: &Intent,
	secrets: &Secrets,
) -> Result<(), String> {
	match step.kind {
		Kind::ApiKey | Kind::AppPassword => credentials::apply(context.config, step, intent),
		Kind::WebhookSecret | Kind::SrsSecret => config::apply(context.path, step, secrets),
		Kind::DkimKey | Kind::DkimDomainKey => dkim::apply(context.config, step, context.now),
		Kind::Restart => Err("the restart is not a store step".to_string()),
	}
}

/// What is left once the value is found in place.
pub(in crate::cli::rotate) fn settle(
	context: &Context,
	step: &Step,
	intent: &Intent,
) -> Result<(), String> {
	credentials::settle(context.config, step, intent)
}

#[cfg(test)]
mod tests;
