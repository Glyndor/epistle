//! The message size cap and the memory budget have to fit together: the
//! SMTP server holds a body in memory while it arrives, so a budget smaller
//! than the largest message would answer every such message with 452,
//! which senders retry for days and then bounce.
//!
//! The minimum transfer rate of a message transaction is checked here too,
//! with its grace period.

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
		self.validate_data_rate()
	}

	/// The rate floor is off at `0` and cannot ask for more than any real
	/// client link gives; its grace must leave a client time to start and
	/// must not hand a slow client its reservation for more than an hour.
	fn validate_data_rate(&self) -> Result<(), ConfigError> {
		if self
			.min_data_rate
			.is_some_and(|rate| rate > MAX_MIN_DATA_RATE)
		{
			return Err(ConfigError::Invalid(format!(
				"min_data_rate must be at most {MAX_MIN_DATA_RATE} bytes per second \
				 (0 turns it off)"
			)));
		}
		if self
			.data_rate_grace
			.is_some_and(|grace| !(1..=MAX_DATA_RATE_GRACE_SECS).contains(&grace))
		{
			return Err(ConfigError::Invalid(format!(
				"data_rate_grace must be between 1 and {MAX_DATA_RATE_GRACE_SECS} seconds"
			)));
		}
		Ok(())
	}
}

/// The highest `min_data_rate` accepted: 1 GiB/s.
const MAX_MIN_DATA_RATE: u64 = 1024 * 1024 * 1024;

/// The longest `data_rate_grace` accepted, in seconds.
const MAX_DATA_RATE_GRACE_SECS: u64 = 3600;

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

	#[test]
	fn a_rate_floor_and_grace_in_range_are_accepted() {
		for settings in [
			"min_data_rate = 0",
			"min_data_rate = 20480\ndata_rate_grace = 300",
			"min_data_rate = 1073741824",
			"data_rate_grace = 1",
			"data_rate_grace = 3600",
		] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
	}

	#[test]
	fn a_grace_outside_one_second_to_an_hour_is_refused() {
		// No grace cuts every client before its first octet arrives; a
		// grace longer than an hour gives a slow client its reservation
		// back for that long.
		for settings in ["data_rate_grace = 0", "data_rate_grace = 3601"] {
			assert_eq!(
				validate(settings),
				Err(
					"invalid configuration: data_rate_grace must be between 1 and 3600 seconds"
						.to_string()
				),
				"{settings}"
			);
		}
	}

	#[test]
	fn a_floor_above_one_gib_per_second_is_refused() {
		assert_eq!(
			validate("min_data_rate = 1073741825"),
			Err("invalid configuration: min_data_rate must be at most 1073741824 bytes per second (0 turns it off)"
				.to_string())
		);
	}
}
