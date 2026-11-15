//! `epistle domain set`: parse CLI units, then commit role and limits through
//! the same data-directory change as the management API.

use crate::cli::limits::{Key, parse_override};

use crate::dns::skip::DomainRole;

use super::writers::Commit;

/// What `domain set` was asked to do with each override: `None` leaves it
/// alone, `Some(None)` removes it and `Some(Some(n))` sets it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Change {
	pub quota: Option<Option<u64>>,
	pub submission_rate: Option<Option<u64>>,
	/// The role the domain is given, `None` to leave it.
	pub role: Option<DomainRole>,
}

/// Turn one `--flag VALUE` / `--no-flag` pair into a [`Change`] entry.
fn parse(
	key: Key,
	flag: &str,
	value: Option<&str>,
	remove: bool,
) -> Result<Option<Option<u64>>, String> {
	if remove {
		return Ok(Some(None));
	}
	let Some(input) = value else {
		return Ok(None);
	};
	let parsed = parse_override(key, input)?;
	if matches!(key, Key::SubmissionRate) && parsed == 0 {
		return Err(format!(
			"{flag}: 0 would remove the limit; use --no-{flag} to remove it"
		));
	}
	Ok(Some(Some(parsed)))
}

impl Change {
	/// Parse the four flags of `domain set`.
	pub(super) fn parse(
		(quota, no_quota): (Option<&str>, bool),
		(rate, no_rate): (Option<&str>, bool),
	) -> Result<Self, String> {
		Ok(Change {
			quota: parse(Key::Quota, "quota", quota, no_quota)?,
			submission_rate: parse(Key::SubmissionRate, "submission-rate", rate, no_rate)?,
			role: None,
		})
	}

	/// The same change, also giving the domain a role.
	pub(super) fn with_role(mut self, role: Option<DomainRole>) -> Self {
		self.role = role;
		self
	}
}

/// The commit of `domain set`: the JSON names only the overrides it touched.
pub(super) fn commit<'a>(domain: &str, change: &Change) -> Commit<'a> {
	let mut fields = serde_json::json!({ "domain": domain });
	if let Some(quota) = change.quota {
		fields["quota"] = quota.into();
	}
	if let Some(rate) = change.submission_rate {
		fields["submission_rate"] = rate.into();
	}
	if let Some(role) = change.role {
		fields["role"] = role.name().into();
	}
	Commit {
		subject: format!("domain {domain}"),
		verb: "updated",
		already: "set that way",
		action: "set",
		fields,
		records_for: None,
	}
}
