use clap::ValueEnum;

use crate::config::Config;

use super::values::Unit;

/// Numeric server settings accepted by `epistle limits`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Key {
	/// Default per-account storage quota.
	Quota,
	/// Per-account submitted messages per minute.
	SubmissionRate,
	/// New recipients per account in a rolling day.
	NewRecipientsPerDay,
	/// Outbound queue give-up window.
	QueueGiveUp,
	/// Outbound wait after the first failed attempt.
	QueueRetryBase,
	/// Longest outbound wait between attempts.
	QueueRetryCap,
	/// Message age of the delay warning.
	QueueDelayWarning,
	/// Inbound messages per client IP per minute.
	InboundRatePerIp,
	/// Inbound messages per envelope sender per minute.
	InboundRatePerSender,
	/// Concurrent connections per listener.
	MaxConnectionsPerListener,
	/// Masked addresses per account.
	MaskedAddressesMax,
	/// First-time sender delay.
	FirstTimeSenderDelay,
	/// Greylist deferral window.
	GreylistDelay,
	/// Outbound conversations at once, all destinations together.
	QueueConcurrency,
	/// Outbound conversations at once with one recipient domain.
	QueuePerDomainConcurrency,
	/// How long a destination that asks to slow down is held off, one
	/// wait per deferral in a row (a comma-separated list).
	QueueBackoff,
}

impl Key {
	pub(super) const ALL: [Self; 16] = [
		Self::Quota,
		Self::SubmissionRate,
		Self::NewRecipientsPerDay,
		Self::QueueGiveUp,
		Self::QueueRetryBase,
		Self::QueueRetryCap,
		Self::QueueDelayWarning,
		Self::InboundRatePerIp,
		Self::InboundRatePerSender,
		Self::MaxConnectionsPerListener,
		Self::MaskedAddressesMax,
		Self::FirstTimeSenderDelay,
		Self::GreylistDelay,
		Self::QueueConcurrency,
		Self::QueuePerDomainConcurrency,
		Self::QueueBackoff,
	];

	pub(super) fn name(self) -> &'static str {
		match self {
			Self::Quota => "quota",
			Self::SubmissionRate => "submission-rate",
			Self::NewRecipientsPerDay => "new-recipients-per-day",
			Self::QueueGiveUp => "queue-give-up",
			Self::QueueRetryBase => "queue-retry-base",
			Self::QueueRetryCap => "queue-retry-cap",
			Self::QueueDelayWarning => "queue-delay-warning",
			Self::InboundRatePerIp => "inbound-rate-per-ip",
			Self::InboundRatePerSender => "inbound-rate-per-sender",
			Self::MaxConnectionsPerListener => "max-connections-per-listener",
			Self::MaskedAddressesMax => "masked-addresses-max",
			Self::FirstTimeSenderDelay => "first-time-sender-delay",
			Self::GreylistDelay => "greylist-delay",
			Self::QueueConcurrency => "queue-concurrency",
			Self::QueuePerDomainConcurrency => "queue-per-domain-concurrency",
			Self::QueueBackoff => "queue-backoff",
		}
	}

	pub(super) fn field(self) -> &'static str {
		match self {
			Self::Quota => "quota_bytes",
			Self::SubmissionRate => "submission_rate_limit_per_min",
			Self::NewRecipientsPerDay => "new_recipients_per_day",
			Self::QueueGiveUp => "queue_give_up_secs",
			Self::QueueRetryBase => "queue_retry_base_secs",
			Self::QueueRetryCap => "queue_retry_cap_secs",
			Self::QueueDelayWarning => "queue_delay_warning_secs",
			Self::InboundRatePerIp => "inbound_rate_limit_per_ip_per_min",
			Self::InboundRatePerSender => "inbound_rate_limit_per_sender_per_min",
			Self::MaxConnectionsPerListener => "max_connections_per_listener",
			Self::MaskedAddressesMax => "masked_addresses_max",
			Self::FirstTimeSenderDelay => "first_time_sender_delay_secs",
			Self::GreylistDelay => "greylist_delay_secs",
			Self::QueueConcurrency => "concurrency",
			Self::QueuePerDomainConcurrency => "per_domain_concurrency",
			Self::QueueBackoff => "backoff_steps",
		}
	}

	/// The table the key lives in, when it is not a top-level one.
	pub(super) fn table(self) -> Option<&'static str> {
		match self {
			Self::QueueConcurrency | Self::QueuePerDomainConcurrency | Self::QueueBackoff => {
				Some("queue")
			}
			_ => None,
		}
	}

	/// Whether the key takes a comma-separated list of values.
	pub(super) fn is_list(self) -> bool {
		matches!(self, Self::QueueBackoff)
	}

	/// The values of a list key in effect, and whether they are the
	/// built-in default.
	pub(super) fn list(self, config: &Config) -> Option<(Vec<u64>, bool)> {
		match self {
			Self::QueueBackoff => {
				let steps = config.queue.backoff_steps.clone();
				let default = steps == crate::queue::backoff::DEFAULT_STEPS;
				Some((steps, default))
			}
			_ => None,
		}
	}

	pub(super) fn unit(self) -> Unit {
		match self {
			Self::Quota => Unit::Size,
			Self::QueueGiveUp
			| Self::QueueRetryBase
			| Self::QueueRetryCap
			| Self::QueueDelayWarning
			| Self::FirstTimeSenderDelay
			| Self::GreylistDelay
			| Self::QueueBackoff => Unit::Duration,
			_ => Unit::Count,
		}
	}

	pub(super) fn max(self) -> u64 {
		match self {
			Self::SubmissionRate
			| Self::NewRecipientsPerDay
			| Self::InboundRatePerIp
			| Self::InboundRatePerSender => u32::MAX as u64,
			Self::MaxConnectionsPerListener | Self::MaskedAddressesMax => {
				(usize::MAX as u64).min(i64::MAX as u64)
			}
			Self::QueueConcurrency | Self::QueuePerDomainConcurrency => {
				crate::queue::limits::MAX_CONCURRENCY as u64
			}
			Self::QueueBackoff => crate::queue::backoff::MAX_STEP_SECS,
			_ => i64::MAX as u64,
		}
	}

	pub(super) fn value(self, config: &Config) -> Option<u64> {
		match self {
			Self::Quota => config.quota_bytes,
			Self::SubmissionRate => config.submission_rate_limit_per_min.map(u64::from),
			Self::NewRecipientsPerDay => config.new_recipients_per_day.map(u64::from),
			Self::QueueGiveUp => config.queue_give_up_secs.filter(|value| *value != 0),
			Self::QueueRetryBase => config.queue_retry_base_secs.filter(|value| *value != 0),
			Self::QueueRetryCap => config.queue_retry_cap_secs.filter(|value| *value != 0),
			Self::QueueDelayWarning => config.queue_delay_warning_secs.filter(|value| *value != 0),
			Self::InboundRatePerIp => config.inbound_rate_limit_per_ip_per_min.map(u64::from),
			Self::InboundRatePerSender => {
				config.inbound_rate_limit_per_sender_per_min.map(u64::from)
			}
			Self::MaxConnectionsPerListener => config
				.max_connections_per_listener
				.filter(|value| *value != 0)
				.map(|value| value as u64),
			Self::MaskedAddressesMax => Some(config.masked_addresses_max as u64),
			Self::FirstTimeSenderDelay => Some(config.first_time_sender_delay_secs),
			Self::GreylistDelay => Some(config.greylist_delay_secs),
			Self::QueueConcurrency => Some(config.queue.concurrency as u64),
			Self::QueuePerDomainConcurrency => Some(config.queue.per_domain_concurrency as u64),
			Self::QueueBackoff => None,
		}
	}

	pub(super) fn default_value(self) -> Option<u64> {
		match self {
			Self::Quota => Some(crate::imap::session::DEFAULT_QUOTA_BYTES),
			Self::QueueGiveUp => Some(5 * 86400),
			Self::QueueRetryBase => Some(crate::queue::schedule::DEFAULT_BASE_SECS),
			Self::QueueRetryCap => Some(crate::queue::schedule::DEFAULT_CAP_SECS),
			Self::QueueDelayWarning => Some(crate::queue::schedule::DEFAULT_DELAY_WARNING_SECS),
			Self::MaskedAddressesMax => Some(100),
			Self::FirstTimeSenderDelay | Self::GreylistDelay => Some(0),
			Self::QueueConcurrency => Some(crate::queue::limits::DEFAULT_CONCURRENCY as u64),
			Self::QueuePerDomainConcurrency => {
				Some(crate::queue::limits::DEFAULT_PER_DOMAIN_CONCURRENCY as u64)
			}
			_ => None,
		}
	}
}
