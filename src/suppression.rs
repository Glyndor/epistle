use crate::queue::SuppressionList;

pub(crate) const MAX_REASON: usize = 512;
pub(crate) const CLI_DEFAULT_REASON: &str = "added by hand (epistle suppression add)";
pub(crate) const API_DEFAULT_REASON: &str = "added by hand (POST /api/v1/suppression)";

pub(crate) struct Added {
	pub(crate) address: String,
	pub(crate) reason: Option<String>,
	pub(crate) changed: bool,
}

pub(crate) enum AddError {
	InvalidAddress(String),
	InvalidReason(String),
	Storage(std::io::Error),
}

pub(crate) fn reason_problem(reason: &str) -> Option<String> {
	if reason.chars().any(char::is_control) {
		return Some("the reason must not contain control characters".into());
	}
	if reason
		.chars()
		.any(crate::util::validation::is_invisible_format)
	{
		return Some(
			"the reason must not contain invisible formatting characters (such as a right-to-left override)"
				.into(),
		);
	}
	if reason.chars().count() > MAX_REASON {
		return Some(format!(
			"the reason must be at most {MAX_REASON} characters"
		));
	}
	None
}

pub(crate) fn add(
	list: &SuppressionList,
	address: &str,
	account_keys: &[String],
	reason: Option<&str>,
	default_reason: &str,
) -> Result<Added, AddError> {
	crate::util::address_reason::parse(address).map_err(AddError::InvalidAddress)?;
	let reason = reason.unwrap_or(default_reason);
	if let Some(problem) = reason_problem(reason) {
		return Err(AddError::InvalidReason(problem));
	}
	let address = crate::util::address::normalize(address);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0);
	let mut changed = false;
	if account_keys.is_empty() {
		changed = list
			.try_suppress_because_once(&address, reason, now)
			.map_err(AddError::Storage)?;
	} else {
		for account in account_keys {
			changed |= list
				.try_suppress_for_because_once(account, &address, reason, now)
				.map_err(AddError::Storage)?;
		}
	}
	let stored_reason = if changed {
		Some(reason.to_owned())
	} else if account_keys.is_empty() {
		list.entry(&address).and_then(|entry| entry.reason)
	} else {
		account_keys
			.iter()
			.find_map(|account| list.entry_for(account, &address))
			.and_then(|entry| entry.reason)
	};
	Ok(Added {
		address,
		reason: stored_reason,
		changed,
	})
}
