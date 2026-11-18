//! The `[queue.undo_send]` section: hold the mail an account submits for a
//! while before anything is delivered, so the sender can take it back.
//!
//! It is off by default: with no section, or `delay_secs = 0`, a submission
//! is handled the instant it is accepted, exactly as before this section
//! existed. The operator sets a server-wide delay and a ceiling
//! (`max_secs`), and may give a tenant, a domain or an account another
//! delay with `[[queue.undo_send.scope]]`; the most specific scope wins and
//! `0` turns the delay off for it. No delay is ever longer than `max_secs`,
//! and `max_secs` itself never exceeds [`HARD_MAX_SECS`].
//!
//! The delay applies to mail an authenticated account submits (SMTP after
//! AUTH, the API, JMAP). Mail that arrives from elsewhere and the reports
//! and bounces the server writes are never held.

use std::collections::HashSet;

use serde::Deserialize;

use super::{Config, ConfigError};

/// The ceiling `max_secs` may be given: ten minutes. A held message sits on
/// disk and is not yet in the queue, so the hold is kept short.
pub const HARD_MAX_SECS: u32 = 600;

/// The ceiling on any delay when `max_secs` is not set: two minutes.
pub const DEFAULT_MAX_SECS: u32 = 120;

/// The `[queue.undo_send]` configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UndoSend {
	/// Seconds a submission is held before delivery, for every account no
	/// scope says otherwise about. `0` (the default) holds nothing.
	pub delay_secs: u32,
	/// The longest any scope may hold a submission, in seconds. Between 0
	/// and [`HARD_MAX_SECS`]; `0` makes the feature unavailable.
	pub max_secs: u32,
	/// Another delay for one tenant, domain or account.
	pub scope: Vec<UndoScope>,
}

impl Default for UndoSend {
	fn default() -> Self {
		UndoSend {
			delay_secs: 0,
			max_secs: DEFAULT_MAX_SECS,
			scope: Vec::new(),
		}
	}
}

/// One `[[queue.undo_send.scope]]` entry: the delay for a tenant, a domain
/// or an account. It names exactly one of the three.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UndoScope {
	/// The `name` of a `[[tenant]]`: every domain of the tenant.
	pub tenant: Option<String>,
	/// A hosted domain, which must also be in `domains`.
	pub domain: Option<String>,
	/// An account name, from any source. Not checked against a list: an
	/// unknown name has no effect.
	pub account: Option<String>,
	/// Seconds the scope holds a submission; `0` turns the hold off for it.
	pub delay_secs: u32,
}

impl UndoScope {
	/// The one target the entry names and its kind, or `None` when it names
	/// none or several.
	pub fn target(&self) -> Option<(&'static str, &str)> {
		let named = [
			("tenant", self.tenant.as_deref()),
			("domain", self.domain.as_deref()),
			("account", self.account.as_deref()),
		];
		let mut found = named
			.iter()
			.filter_map(|(kind, name)| name.map(|n| (*kind, n)));
		match (found.next(), found.next()) {
			(Some(one), None) => Some(one),
			_ => None,
		}
	}
}

impl Config {
	/// The checks of `[queue.undo_send]`: every number within the ceiling,
	/// and every scope names one target the file declares, once.
	pub(super) fn validate_undo_send(&self) -> Result<(), ConfigError> {
		let section = &self.queue.undo_send;
		let invalid = |message: String| Err(ConfigError::Invalid(message));
		if section.max_secs > HARD_MAX_SECS {
			return invalid(format!(
				"[queue.undo_send] max_secs must be between 0 and {HARD_MAX_SECS} (got {})",
				section.max_secs
			));
		}
		if section.delay_secs > section.max_secs {
			return invalid(format!(
				"[queue.undo_send] delay_secs ({}) must not exceed max_secs ({})",
				section.delay_secs, section.max_secs
			));
		}
		let mut seen = HashSet::new();
		for scope in &section.scope {
			let Some((kind, name)) = scope.target() else {
				return invalid(
					"[[queue.undo_send.scope]] must name exactly one of tenant, domain or account"
						.into(),
				);
			};
			let label = format!("[[queue.undo_send.scope]] {kind} {name:?}");
			if name.trim().is_empty() || name.len() > 253 || name.chars().any(char::is_control) {
				return invalid(format!("{label} is not a usable name"));
			}
			if !seen.insert((kind, name.to_ascii_lowercase())) {
				return invalid(format!("{label} is declared more than once"));
			}
			let declared = match kind {
				"tenant" => self
					.tenants
					.iter()
					.any(|tenant| tenant.name.as_deref() == Some(name)),
				"domain" => self
					.domains
					.iter()
					.any(|domain| domain.eq_ignore_ascii_case(name)),
				_ => true,
			};
			if !declared {
				return invalid(format!("{label} is not declared in this file"));
			}
			if scope.delay_secs > section.max_secs {
				return invalid(format!(
					"{label} delay_secs ({}) must not exceed max_secs ({})",
					scope.delay_secs, section.max_secs
				));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
