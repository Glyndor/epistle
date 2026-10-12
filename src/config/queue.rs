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
}

const fn default_tlsrpt_reports() -> bool {
	true
}

impl Default for Queue {
	fn default() -> Self {
		Queue {
			outbound_tls: OutboundTls::default(),
			tlsrpt_reports: default_tlsrpt_reports(),
		}
	}
}

impl super::Config {
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
}
