//! DKIM keys: the `[dkim]` key and every `[[dkim.domain]]` key.
//!
//! The CLI never rotates a DKIM key itself: it leaves a request the server
//! serves, which makes the key, publishes its record and switches. The
//! journal records the selector in service when the request was made. A
//! later run counts the step as done when the request is still waiting or
//! the selector has changed, so a rotation the server already served is not
//! asked for again on another day.

use crate::cli::serve::tasks::{
	DkimRotationPlan, DnsWrite, decide_dkim_rotation, decide_domain_rotation,
};
use crate::config::Config;
use crate::dkim::{domain_rotate, rotate};

use super::super::journal::{Intent, Kind, Step};

/// The DKIM steps, after the server's own checks, and a note for each key
/// this server cannot rotate. A refusal stops the run before it changes
/// anything.
pub(super) fn plan(config: &Config, now: u64) -> Result<(Vec<Step>, Vec<String>), String> {
	let (mut steps, mut notes) = (Vec::new(), Vec::new());
	if config.dkim.is_none() {
		return Ok((steps, notes));
	}
	let write = DnsWrite::for_install(config);
	match decide_dkim_rotation(config, &write) {
		DkimRotationPlan::Run {
			signing_domains,
			out_of_zone,
			..
		} if signing_domains.is_empty() && out_of_zone.is_empty() => {}
		DkimRotationPlan::Run { .. } => {
			crate::cli::dkim::preflight(config, now)
				.map_err(|reason| format!("dkim-signing-key: the [dkim] key: {reason}"))?;
			steps.push(Step::pending(Kind::DkimKey, "", None));
		}
		DkimRotationPlan::Off => notes.push(
			"dkim-signing-key: the [dkim] key does not rotate on this server, because no [dns] \
			 entry publishes its records; make a new key with `epistle dkim-keygen`, publish its \
			 selector and point [dkim] at it"
				.to_string(),
		),
	}
	let domains = decide_domain_rotation(config, &write);
	for domain in &domains.rotating {
		crate::cli::dkim::rotate_domain::preflight(config, domain, now)
			.map_err(|reason| format!("dkim-signing-key: {domain}: {reason}"))?;
		steps.push(Step::pending(Kind::DkimDomainKey, domain, None));
	}
	for domain in &domains.unmanaged {
		notes.push(format!(
			"dkim-signing-key: the key of {domain} does not rotate on this server, because no \
			 [dns] entry publishes at it; replace its [[dkim.domain]] key and publish the selector"
		));
	}
	Ok((steps, notes))
}

/// The selector in service for the step's key.
fn active(config: &Config, step: &Step) -> Result<String, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	if step.kind == Kind::DkimKey {
		return rotate::active_ed25519(dkim, &config.data_dir)
			.map(|key| key.selector)
			.map_err(|error| error.to_string());
	}
	let entry = dkim
		.override_for(&step.item)
		.ok_or_else(|| format!("{} has no [[dkim.domain]] key any more", step.item))?;
	domain_rotate::active_keys(entry, &config.data_dir)
		.map(|keys| keys.ed.selector)
		.map_err(|error| error.to_string())
}

fn waiting(config: &Config, step: &Step) -> bool {
	match step.kind {
		Kind::DkimKey => rotate::pending_request(&config.data_dir).is_some(),
		_ => domain_rotate::pending_request(&config.data_dir, &step.item).is_some(),
	}
}

/// Record the selector the request replaces.
pub(super) fn prepare(config: &Config, step: &Step) -> Result<Intent, String> {
	Ok(Intent::Queued {
		active: active(config, step)?,
	})
}

/// Whether the request is waiting or the server has served it.
pub(super) fn landed(config: &Config, step: &Step, recorded: &str) -> Result<bool, String> {
	Ok(waiting(config, step) || active(config, step)? != recorded)
}

/// Leave the request for the server.
pub(super) fn apply(config: &Config, step: &Step, now: u64) -> Result<(), String> {
	match step.kind {
		Kind::DkimKey => rotate::request_rotation(&config.data_dir, now)
			.map_err(|error| format!("cannot write the rotation request: {error}")),
		_ => domain_rotate::request_rotation(&config.data_dir, &step.item, now).map_err(|error| {
			format!(
				"cannot write the rotation request of {}: {error}",
				step.item
			)
		}),
	}
}
