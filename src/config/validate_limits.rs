//! The message size cap and the memory budget have to fit together: the
//! SMTP server holds a body in memory while it arrives, so a budget smaller
//! than the largest message would answer every such message with 452,
//! which senders retry for days and then bounce.

use super::{Config, ConfigError};

impl Config {
	/// Refuse a `max_message_size` that does not fit this platform's
	/// addresses, or that the effective `message_memory_budget` (unless it
	/// is turned off with `0`) could never hold.
	pub(super) fn validate_message_limits(&self) -> Result<(), ConfigError> {
		let size = match self.max_message_size {
			None | Some(0) => crate::smtp::session::MAX_MESSAGE_SIZE as u64,
			Some(size) => size,
		};
		if usize::try_from(size).is_err() {
			return Err(ConfigError::Invalid(format!(
				"max_message_size ({size} bytes) is larger than this platform can address"
			)));
		}
		let budget = self
			.message_memory_budget
			.unwrap_or(crate::smtp::memory_budget::DEFAULT_BUDGET_BYTES);
		if budget != 0 && budget < size {
			return Err(ConfigError::Invalid(format!(
				"message_memory_budget ({budget} bytes) is smaller than max_message_size \
				 ({size} bytes), so a message of the largest size could never be received; \
				 raise message_memory_budget, lower max_message_size, or set \
				 message_memory_budget = 0 to turn the budget off"
			)));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn validate(settings: &str) -> Result<(), String> {
		let config: Config = toml::from_str(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{settings}"
		))
		.expect("parse");
		config.validate().map_err(|error| error.to_string())
	}

	#[test]
	fn a_budget_smaller_than_the_largest_message_is_refused() {
		let error = validate("max_message_size = 26214400\nmessage_memory_budget = 10485760")
			.expect_err("refused");
		assert!(
			error.contains("message_memory_budget") && error.contains("max_message_size"),
			"the refusal names both keys: {error}"
		);
	}

	#[test]
	fn a_message_size_over_the_default_budget_is_refused() {
		let error = validate("max_message_size = 314572800").expect_err("refused");
		assert!(error.contains("message_memory_budget"), "{error}");
	}

	#[test]
	fn caps_that_fit_together_are_accepted() {
		assert_eq!(validate(""), Ok(()));
		assert_eq!(
			validate("max_message_size = 10485760\nmessage_memory_budget = 10485760"),
			Ok(())
		);
		assert_eq!(
			validate("max_message_size = 314572800\nmessage_memory_budget = 0"),
			Ok(()),
			"a budget turned off holds any size"
		);
		assert_eq!(
			validate("max_message_size = 0"),
			Ok(()),
			"0 is the default size"
		);
	}
}
