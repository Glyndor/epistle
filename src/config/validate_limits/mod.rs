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

	/// `max_recipients` stays within what RFC 5321 §4.5.3.1.8 demands of a
	/// server (at least 100 recipients per message) and what one message
	/// may ask of the server (at most [`MAX_MAX_RECIPIENTS`]).
	pub(super) fn validate_max_recipients(&self) -> Result<(), ConfigError> {
		use crate::smtp::session::{
			MAX_MAX_RECIPIENTS, MIN_MAX_RECIPIENTS, MIN_MAX_RECIPIENTS_REASON,
		};
		let Some(count) = self.max_recipients else {
			return Ok(());
		};
		if count < MIN_MAX_RECIPIENTS {
			return Err(ConfigError::Invalid(format!(
				"max_recipients ({count}) is below {MIN_MAX_RECIPIENTS}: {MIN_MAX_RECIPIENTS_REASON}"
			)));
		}
		if count > MAX_MAX_RECIPIENTS {
			return Err(ConfigError::Invalid(format!(
				"max_recipients ({count}) is above {MAX_MAX_RECIPIENTS}, the most one message \
				 may name"
			)));
		}
		Ok(())
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
		self.validate_connection_caps()?;
		self.validate_preauth_timeout()
	}

	fn validate_connection_caps(&self) -> Result<(), ConfigError> {
		for (name, cap) in [
			(
				"max_connections_per_listener",
				self.max_connections_per_listener,
			),
			("max_http_connections", self.max_http_connections),
		] {
			if cap.is_some_and(|cap| cap > crate::net::conn_limit::MAX_CONNECTIONS) {
				return Err(ConfigError::Invalid(format!(
					"{name} must be at most {} connections",
					crate::net::conn_limit::MAX_CONNECTIONS
				)));
			}
		}
		Ok(())
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
		self.validate_per_account_caps()
	}

	/// The singular `max_connections_per_account` is not wired to any
	/// guard: `MailboxLimits::from_config` only reads `_per_ip` and
	/// `_total`. Reject it up front so an operator who set the singular
	/// key does not silently keep the 10/50 defaults they meant to
	/// override.
	fn validate_per_account_caps(&self) -> Result<(), ConfigError> {
		if self.max_connections_per_account.is_some() {
			return Err(ConfigError::Invalid(
				"max_connections_per_account is not configurable; use \
				 max_connections_per_account_per_ip (per (account, client IP)) and \
				 max_connections_per_account_total (per account)"
					.into(),
			));
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
mod tests;
