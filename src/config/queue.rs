//! Outbound queue configuration: the `[queue]` section.
//!
//! `outbound_tls` selects how the STARTTLS certificate of a recipient MX is
//! authenticated; its default is the most restrictive option (strict PKIX
//! verification), so an absent `[queue]` section leaves existing deployments
//! unchanged (fail closed). `tlsrpt_reports` turns the outbound TLS-RPT
//! reports off.

use serde::Deserialize;

/// How outbound STARTTLS authenticates the recipient MX certificate when TLS is
/// neither mandated (MTA-STS enforce / REQUIRETLS) nor authenticated by DANE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundTls {
	/// Strict PKIX: the certificate must chain to a webpki trust anchor and
	/// match the MX hostname, exactly like a browser (the default). A remote
	/// with a self-signed or expired certificate and no DANE/MTA-STS is
	/// deferred rather than sent in the clear.
	#[default]
	Strict,
	/// Opportunistic: complete the handshake with any certificate (encryption
	/// without authentication). This is the historical SMTP norm — it stops
	/// passive eavesdropping but not an active man-in-the-middle — and is opt
	/// in. MTA-STS enforce, REQUIRETLS and DANE still authenticate regardless.
	Opportunistic,
}

/// The `[queue]` configuration section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Queue {
	/// Outbound STARTTLS authentication mode for unmandated, non-DANE delivery.
	/// Defaults to [`OutboundTls::Strict`].
	#[serde(default)]
	pub outbound_tls: OutboundTls,
	/// Record the TLS outcome of each delivery and send the daily TLS-RPT
	/// report (RFC 8460) to every recipient domain that asks for one.
	/// Defaults to `true`.
	#[serde(default = "default_tlsrpt_reports")]
	pub tlsrpt_reports: bool,
	/// Outbound conversations running at once, all destinations together.
	/// Defaults to [`crate::queue::limits::DEFAULT_CONCURRENCY`].
	#[serde(default = "default_concurrency")]
	pub concurrency: usize,
	/// Outbound conversations running at once with any one recipient domain.
	/// Defaults to [`crate::queue::limits::DEFAULT_PER_DOMAIN_CONCURRENCY`].
	#[serde(default = "default_per_domain_concurrency")]
	pub per_domain_concurrency: usize,
	/// How long a destination that asks to slow down is held off, in
	/// seconds, one step per deferral in a row, the last repeating.
	/// Defaults to [`crate::queue::backoff::DEFAULT_STEPS`].
	#[serde(default = "default_backoff_steps")]
	pub backoff_steps: Vec<u64>,
}

fn default_backoff_steps() -> Vec<u64> {
	crate::queue::backoff::DEFAULT_STEPS.to_vec()
}

const fn default_concurrency() -> usize {
	crate::queue::limits::DEFAULT_CONCURRENCY
}

const fn default_per_domain_concurrency() -> usize {
	crate::queue::limits::DEFAULT_PER_DOMAIN_CONCURRENCY
}

const fn default_tlsrpt_reports() -> bool {
	true
}

impl Default for Queue {
	fn default() -> Self {
		Queue {
			outbound_tls: OutboundTls::default(),
			tlsrpt_reports: default_tlsrpt_reports(),
			concurrency: default_concurrency(),
			per_domain_concurrency: default_per_domain_concurrency(),
			backoff_steps: default_backoff_steps(),
		}
	}
}

impl super::Config {
	/// The conversation caps must allow at least one conversation, stay
	/// within what one process should open, and not give one domain more
	/// than the total.
	pub(super) fn validate_queue_limits(&self) -> Result<(), super::ConfigError> {
		use crate::queue::limits::MAX_CONCURRENCY;
		let queue = &self.queue;
		let invalid = |message: String| Err(super::ConfigError::Invalid(message));
		if !(1..=MAX_CONCURRENCY).contains(&queue.concurrency) {
			return invalid(format!(
				"[queue] concurrency must be between 1 and {MAX_CONCURRENCY} (got {})",
				queue.concurrency
			));
		}
		if !(1..=queue.concurrency).contains(&queue.per_domain_concurrency) {
			return invalid(format!(
				"[queue] per_domain_concurrency must be between 1 and concurrency ({}) (got {})",
				queue.concurrency, queue.per_domain_concurrency
			));
		}
		self.validate_backoff_steps()
	}

	/// The backoff needs at least one step and at most
	/// [`crate::queue::backoff::MAX_STEPS`], each between a second and a day.
	fn validate_backoff_steps(&self) -> Result<(), super::ConfigError> {
		use crate::queue::backoff::{MAX_STEP_SECS, MAX_STEPS};
		let steps = &self.queue.backoff_steps;
		if steps.is_empty() || steps.len() > MAX_STEPS {
			return Err(super::ConfigError::Invalid(format!(
				"[queue] backoff_steps must have between 1 and {MAX_STEPS} steps (got {})",
				steps.len()
			)));
		}
		if let Some(step) = steps
			.iter()
			.find(|step| !(1..=MAX_STEP_SECS).contains(*step))
		{
			return Err(super::ConfigError::Invalid(format!(
				"[queue] backoff_steps must be between 1 and {MAX_STEP_SECS} seconds each (got {step})"
			)));
		}
		Ok(())
	}

	/// The outbound retry schedule must make sense: a first wait of at least
	/// a minute, a cap not below it, and a delay warning that comes before
	/// the give-up window closes.
	pub(super) fn validate_retry_schedule(&self) -> Result<(), super::ConfigError> {
		use crate::queue::schedule::{MIN_BASE_SECS, RetrySchedule};
		let invalid = |message: String| Err(super::ConfigError::Invalid(message));
		let schedule = RetrySchedule::from_config(
			self.queue_retry_base_secs,
			self.queue_retry_cap_secs,
			self.queue_delay_warning_secs,
		);
		let give_up = self
			.queue_give_up_secs
			.filter(|secs| *secs != 0)
			.unwrap_or(5 * 86_400);
		if schedule.base < MIN_BASE_SECS {
			return invalid(format!(
				"queue_retry_base_secs must be at least {MIN_BASE_SECS} (got {})",
				schedule.base
			));
		}
		if schedule.cap < schedule.base {
			return invalid(format!(
				"queue_retry_cap_secs ({}) must not be below queue_retry_base_secs ({})",
				schedule.cap, schedule.base
			));
		}
		if schedule.delay_warning >= give_up {
			return invalid(format!(
				"queue_delay_warning_secs ({}) must be below the give-up window \
				 queue_give_up_secs ({give_up})",
				schedule.delay_warning
			));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tlsrpt_reports_default_on_and_can_be_turned_off() {
		assert!(Queue::default().tlsrpt_reports);
		let parsed: Queue = toml::from_str("outbound_tls = \"strict\"").expect("parse");
		assert!(parsed.tlsrpt_reports);
		let off: Queue = toml::from_str("tlsrpt_reports = false").expect("parse");
		assert!(!off.tlsrpt_reports);
	}

	fn with_queue(section: &str) -> crate::config::Config {
		toml::from_str(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[queue]\n{section}"
		))
		.expect("parse")
	}

	#[test]
	fn concurrency_out_of_range_is_refused() {
		for (section, message) in [
			(
				"concurrency = 0",
				"[queue] concurrency must be between 1 and 1024 (got 0)",
			),
			(
				"concurrency = 1025",
				"[queue] concurrency must be between 1 and 1024 (got 1025)",
			),
			(
				"per_domain_concurrency = 0",
				"[queue] per_domain_concurrency must be between 1 and concurrency (8) (got 0)",
			),
			(
				"concurrency = 4\nper_domain_concurrency = 5",
				"[queue] per_domain_concurrency must be between 1 and concurrency (4) (got 5)",
			),
		] {
			let error = with_queue(section)
				.validate_queue_limits()
				.expect_err(section);
			assert_eq!(
				error.to_string(),
				format!("invalid configuration: {message}")
			);
		}
		assert!(
			with_queue("concurrency = 16\nper_domain_concurrency = 16")
				.validate_queue_limits()
				.is_ok()
		);
	}

	#[test]
	fn backoff_steps_default_parse_and_are_bounded() {
		assert_eq!(Queue::default().backoff_steps, [60, 300, 900, 3600]);
		let parsed = with_queue("backoff_steps = [30, 120]");
		assert_eq!(parsed.queue.backoff_steps, [30, 120]);
		assert!(parsed.validate_queue_limits().is_ok());
		for (section, message) in [
			(
				"backoff_steps = []",
				"[queue] backoff_steps must have between 1 and 16 steps (got 0)",
			),
			(
				"backoff_steps = [60, 0]",
				"[queue] backoff_steps must be between 1 and 86400 seconds each (got 0)",
			),
			(
				"backoff_steps = [86401]",
				"[queue] backoff_steps must be between 1 and 86400 seconds each (got 86401)",
			),
		] {
			let error = with_queue(section)
				.validate_queue_limits()
				.expect_err(section);
			assert_eq!(
				error.to_string(),
				format!("invalid configuration: {message}")
			);
		}
	}

	#[test]
	fn concurrency_defaults_and_parses() {
		let defaults = Queue::default();
		assert_eq!(
			(defaults.concurrency, defaults.per_domain_concurrency),
			(8, 2)
		);
		let parsed: Queue =
			toml::from_str("concurrency = 20\nper_domain_concurrency = 4").expect("parse");
		assert_eq!((parsed.concurrency, parsed.per_domain_concurrency), (20, 4));
	}
}
