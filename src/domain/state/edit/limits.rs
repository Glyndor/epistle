//! The atomic `domain set` used by the command and management API.

use super::super::file::{DomainLimits, DomainsFile, StoredRole};
use super::{EditError, rules};
use crate::config::Config;

pub(super) fn apply(
	current: &Config,
	file: &mut DomainsFile,
	name: &str,
	role: Option<StoredRole>,
	quota: Option<Option<u64>>,
	submission_rate: Option<Option<u32>>,
) -> Result<(), EditError> {
	let name = rules::canonical("domain", name)?;
	if role.is_none() && quota.is_none() && submission_rate.is_none() {
		return Err(EditError::Invalid("domain set: nothing to change".into()));
	}
	if quota.flatten().is_some_and(|value| value > i64::MAX as u64) {
		return Err(EditError::Invalid(
			"quota exceeds the maximum TOML integer".into(),
		));
	}
	if submission_rate == Some(Some(0)) {
		return Err(EditError::Invalid(
			"submission-rate: 0 would remove the limit; use --no-submission-rate to remove it"
				.into(),
		));
	}
	let domain = file
		.domain_mut(&name)
		.ok_or_else(|| EditError::NotFound(format!("domain {name} is not configured")))?;
	if let Some(role) = role {
		domain.role = role;
	}
	let before = DomainLimits {
		quota: current.domain_quotas.get(&name).copied(),
		submission_rate: current.domain_submission_limits.get(&name).copied(),
	};
	let after = DomainLimits {
		quota: quota.unwrap_or(before.quota),
		submission_rate: submission_rate.unwrap_or(before.submission_rate),
	};
	if after != before {
		domain.limits = Some(after);
	}
	Ok(())
}
