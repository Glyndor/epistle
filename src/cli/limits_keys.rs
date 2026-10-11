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
}

impl Key {
	pub(super) const ALL: [Self; 10] = [
		Self::Quota,
		Self::SubmissionRate,
		Self::NewRecipientsPerDay,
		Self::QueueGiveUp,
		Self::InboundRatePerIp,
		Self::InboundRatePerSender,
		Self::MaxConnectionsPerListener,
		Self::MaskedAddressesMax,
		Self::FirstTimeSenderDelay,
		Self::GreylistDelay,
	];

	pub(super) fn name(self) -> &'static str {
		match self {
			Self::Quota => "quota",
			Self::SubmissionRate => "submission-rate",
			Self::NewRecipientsPerDay => "new-recipients-per-day",
			Self::QueueGiveUp => "queue-give-up",
			Self::InboundRatePerIp => "inbound-rate-per-ip",
			Self::InboundRatePerSender => "inbound-rate-per-sender",
			Self::MaxConnectionsPerListener => "max-connections-per-listener",
			Self::MaskedAddressesMax => "masked-addresses-max",
			Self::FirstTimeSenderDelay => "first-time-sender-delay",
			Self::GreylistDelay => "greylist-delay",
		}
	}

	pub(super) fn field(self) -> &'static str {
		match self {
			Self::Quota => "quota_bytes",
			Self::SubmissionRate => "submission_rate_limit_per_min",
			Self::NewRecipientsPerDay => "new_recipients_per_day",
			Self::QueueGiveUp => "queue_give_up_secs",
			Self::InboundRatePerIp => "inbound_rate_limit_per_ip_per_min",
			Self::InboundRatePerSender => "inbound_rate_limit_per_sender_per_min",
			Self::MaxConnectionsPerListener => "max_connections_per_listener",
			Self::MaskedAddressesMax => "masked_addresses_max",
			Self::FirstTimeSenderDelay => "first_time_sender_delay_secs",
			Self::GreylistDelay => "greylist_delay_secs",
		}
	}

	pub(super) fn unit(self) -> Unit {
		match self {
			Self::Quota => Unit::Size,
			Self::QueueGiveUp | Self::FirstTimeSenderDelay | Self::GreylistDelay => Unit::Duration,
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
			_ => i64::MAX as u64,
		}
	}

	pub(super) fn value(self, config: &Config) -> Option<u64> {
		match self {
			Self::Quota => config.quota_bytes,
			Self::SubmissionRate => config.submission_rate_limit_per_min.map(u64::from),
			Self::NewRecipientsPerDay => config.new_recipients_per_day.map(u64::from),
			Self::QueueGiveUp => config.queue_give_up_secs.filter(|value| *value != 0),
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
		}
	}

	pub(super) fn default_value(self) -> Option<u64> {
		match self {
			Self::Quota => Some(crate::imap::session::DEFAULT_QUOTA_BYTES),
			Self::QueueGiveUp => Some(5 * 86400),
			Self::MaskedAddressesMax => Some(100),
			Self::FirstTimeSenderDelay | Self::GreylistDelay => Some(0),
			_ => None,
		}
	}
}
