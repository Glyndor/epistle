//! `epistle domain set`: the per-domain storage quota, submission rate and
//! role. The first two are the `domain_quotas` and `domain_submission_limits` maps that
//! `limits set --domain` edits; both commands parse values the same way.

use crate::cli::config_edit::ConfigDocument;
use crate::cli::limits::{Key, domain_map, parse_override};

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

	/// Write the change into `document` for `domain`.
	pub(super) fn apply(&self, document: &mut ConfigDocument, domain: &str) -> Result<(), String> {
		for (key, change) in [
			(Key::Quota, self.quota),
			(Key::SubmissionRate, self.submission_rate),
		] {
			let Some(change) = change else { continue };
			let map = domain_map(key).ok_or("not a per-domain limit")?;
			match change {
				Some(value) => {
					let value = i64::try_from(value).unwrap_or(i64::MAX);
					document.set_map_entry(map, domain, value)?;
				}
				None => document.remove_map_entry(map, domain)?,
			}
		}
		if let Some(role) = self.role {
			super::role::apply(document, domain, role)?;
		}
		Ok(())
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
