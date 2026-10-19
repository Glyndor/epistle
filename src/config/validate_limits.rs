//! The message size cap and the memory budget have to fit together: the
//! SMTP server holds a body in memory while it arrives, so a budget smaller
//! than the largest message would answer every such message with 452,
//! which senders retry for days and then bounce.
//!
//! The minimum transfer rate of a message transaction is checked here too,
//! with its grace period, and so are the limits that end an SMTP session
//! holding a connection without moving a message forward.

use super::{Config, ConfigError};

impl Config {
	/// Refuse a `max_message_size` that does not fit this platform's
	/// addresses, or that the effective `message_memory_budget` (unless it
	/// is turned off with `0`) could never hold: the configured one, or the
	/// ceiling of the derived one.
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
		let Some(budget) = self.message_memory_budget else {
			// An unset budget is derived from the container's memory and
			// rises to one message of the largest size, up to its ceiling.
			let ceiling = crate::smtp::memory_fit::MAX_DERIVED_BUDGET;
			if size > ceiling {
				return Err(ConfigError::Invalid(format!(
					"max_message_size ({size} bytes) is larger than the {ceiling} bytes a \
					 derived message_memory_budget can reach; set message_memory_budget to at \
					 least max_message_size, or to 0 to turn the budget off"
				)));
			}
			return self.validate_data_rate();
		};
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
		self.validate_session_limits()
	}

	/// Each session limit is off at `0`. A junk limit under ten cuts a
	/// client that sends RSET before every message after a handful, and a
	/// lifetime under a minute cuts one still greeting; past their upper
	/// bounds neither bounds anything worth having.
	fn validate_session_limits(&self) -> Result<(), ConfigError> {
		if self
			.junk_command_limit
			.is_some_and(|limit| limit != 0 && !(10..=MAX_JUNK_COMMAND_LIMIT).contains(&limit))
		{
			return Err(ConfigError::Invalid(format!(
				"junk_command_limit must be 0 (off) or between 10 and {MAX_JUNK_COMMAND_LIMIT}"
			)));
		}
		if self
			.max_session_time
			.is_some_and(|secs| secs != 0 && !(60..=MAX_SESSION_TIME_SECS).contains(&secs))
		{
			return Err(ConfigError::Invalid(format!(
				"max_session_time must be 0 (off) or between 60 and {MAX_SESSION_TIME_SECS} seconds"
			)));
		}
		self.validate_preauth_timeout()
	}

	/// A deadline under five seconds cuts a client still on its TLS
	/// handshake over a slow link; over an hour it bounds nothing.
	fn validate_preauth_timeout(&self) -> Result<(), ConfigError> {
		if self
			.preauth_timeout
			.is_some_and(|secs| !(5..=MAX_PREAUTH_TIMEOUT_SECS).contains(&secs))
		{
			return Err(ConfigError::Invalid(format!(
				"preauth_timeout must be between 5 and {MAX_PREAUTH_TIMEOUT_SECS} seconds"
			)));
		}
		Ok(())
	}
}

/// The longest `preauth_timeout` accepted, in seconds: an hour.
const MAX_PREAUTH_TIMEOUT_SECS: u64 = 3_600;

/// The highest `junk_command_limit` accepted.
const MAX_JUNK_COMMAND_LIMIT: u64 = 10_000;

/// The longest `max_session_time` accepted, in seconds: a day.
const MAX_SESSION_TIME_SECS: u64 = 86_400;

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
	fn a_derived_budget_holds_any_message_up_to_its_ceiling() {
		assert_eq!(
			validate("max_message_size = 314572800"),
			Ok(()),
			"the derived budget rises to one 300 MiB message"
		);
		assert_eq!(validate("max_message_size = 1073741824"), Ok(()));
		assert_eq!(
			validate("max_message_size = 1073741825"),
			Err(
				"invalid configuration: max_message_size (1073741825 bytes) is larger than \
				 the 1073741824 bytes a derived message_memory_budget can reach; set \
				 message_memory_budget to at least max_message_size, or to 0 to turn the \
				 budget off"
					.to_string()
			)
		);
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
	fn session_limits_in_range_are_accepted() {
		for settings in [
			"junk_command_limit = 0",
			"junk_command_limit = 10",
			"junk_command_limit = 10000",
			"max_session_time = 0",
			"max_session_time = 60",
			"max_session_time = 86400",
		] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
	}

	#[test]
	fn a_junk_command_limit_outside_ten_to_ten_thousand_is_refused() {
		// Under ten a client that sends RSET before each message is cut
		// after a handful; past ten thousand the limit no longer bounds
		// anything.
		for settings in ["junk_command_limit = 9", "junk_command_limit = 10001"] {
			assert_eq!(
				validate(settings),
				Err("invalid configuration: junk_command_limit must be 0 (off) or between 10 and 10000"
					.to_string()),
				"{settings}"
			);
		}
	}

	#[test]
	fn a_session_time_outside_a_minute_to_a_day_is_refused() {
		for settings in ["max_session_time = 59", "max_session_time = 86401"] {
			assert_eq!(
				validate(settings),
				Err("invalid configuration: max_session_time must be 0 (off) or between 60 and 86400 seconds"
					.to_string()),
				"{settings}"
			);
		}
	}

	#[test]
	fn a_preauth_timeout_outside_five_seconds_to_an_hour_is_refused() {
		for settings in [
			"preauth_timeout = 0",
			"preauth_timeout = 4",
			"preauth_timeout = 3601",
		] {
			assert_eq!(
				validate(settings),
				Err(
					"invalid configuration: preauth_timeout must be between 5 and 3600 seconds"
						.to_string()
				),
				"{settings}"
			);
		}
		for settings in ["preauth_timeout = 5", "preauth_timeout = 3600"] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
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
