//! A person's display name: free text, kept as written.
//!
//! Unlike an address it is never lowercased or otherwise rewritten: any
//! case and any script is fine. It ends up in a `From` header and in JMAP
//! `Identity.name`, so it is trimmed, bounded, and refused when it carries a
//! control character (CR and LF included), which is what would let it break
//! out of a header line.

/// The longest display name accepted, in characters.
pub const MAX_CHARS: usize = 128;

/// The stored form of a display name: trimmed, `None` when empty, or why it
/// is refused.
pub fn validate(raw: &str) -> Result<Option<String>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Ok(None);
	}
	if trimmed.chars().any(char::is_control) {
		return Err("the display name must not contain control characters or line breaks".into());
	}
	let chars = trimmed.chars().count();
	if chars > MAX_CHARS {
		return Err(format!(
			"the display name is {chars} characters; the maximum is {MAX_CHARS}"
		));
	}
	Ok(Some(trimmed.to_string()))
}

/// [`validate`] for a store write, as a [`super::StoreError`].
pub(super) fn stored(raw: Option<&str>) -> Result<Option<String>, super::StoreError> {
	match raw {
		Some(raw) => validate(raw).map_err(super::StoreError::Invalid),
		None => Ok(None),
	}
}

impl super::AccountStore {
	/// Set (or, with an empty `raw`, clear) a dynamic account's display
	/// name and return what was stored. `NotFound` for static and unknown
	/// accounts; `Invalid` for a name [`validate`] refuses.
	pub fn set_display_name(
		&self,
		name: &str,
		raw: &str,
	) -> Result<Option<String>, super::StoreError> {
		let display_name = validate(raw).map_err(super::StoreError::Invalid)?;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| super::StoreError::NotFound(name.to_string()))?;
			target.display_name = display_name.clone();
			Ok(())
		})?;
		Ok(display_name)
	}

	/// The display name of a static or dynamic account.
	pub fn display_name(&self, name: &str) -> Option<String> {
		if let Some(account) = self.dynamic(name) {
			return account.display_name;
		}
		self.static_accounts
			.iter()
			.find(|account| account.name == name)
			.and_then(|account| account.display_name.clone())
	}
}

#[cfg(test)]
#[path = "display_name_tests.rs"]
mod tests;
