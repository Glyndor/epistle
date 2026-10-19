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
	/// Per-instance message-size cap in bytes. Applies to SMTP DATA / BDAT
	/// and to the JMAP / REST submission paths. Default is 25 MiB.
	MaxMessageSize,
	/// Recipients one message may name, on SMTP, REST send and JMAP
	/// submission. Default is 100, the least RFC 5321 lets a server accept.
	MaxRecipients,
	/// Shared byte budget every DATA / BDAT reservation draws from. The
	/// reservation is released on every path that drops the in-flight
	/// body (success, error, RSET, disconnect). `0` disables the
	/// budget (every reservation succeeds). The default is 256 MiB.
	MessageMemoryBudget,
	/// Per-client-IP concurrent connection cap. A peer over the cap
	/// is answered `421 4.7.0` and closed. Default is 20.
	MaxConnectionsPerIp,
	/// Minimum average rate of one message transaction in bytes per
	/// second, once its grace is over. Default is 10240; `0` turns it off.
	MinDataRate,
	/// Seconds from the start of a message transaction before the rate
	/// floor applies. Default is 120.
	DataRateGrace,
	/// Commands without progress one SMTP session may send before it is
	/// closed with `421 4.7.0`. Default is 100; `0` turns it off.
	JunkCommandLimit,
	/// Seconds one SMTP session may last before it is closed with
	/// `421 4.4.2` at the next command boundary. Default is 1800; `0`
	/// turns it off.
	MaxSessionTime,
	/// Seconds an IMAP, POP3 or ManageSieve client gets, from the start of
	/// the connection, to sign in. Default is 60.
	PreauthTimeout,
	/// Concurrent connections one client may hold on each IMAP, POP3 and
	/// ManageSieve listener. Default is 200.
	MaxMailboxConnectionsPerIp,
	/// Concurrent connections each plain-HTTP listener serves. Default is
	/// 1024.
	MaxHttpConnections,
	/// Concurrent connections one client may hold on each plain-HTTP
	/// listener. Default is 256.
	MaxHttpConnectionsPerIp,
}

impl Key {
	/// Every adjustable key, in the order the catalog lists it.
	/// `catalog::ADJUSTABLE` is the catalog's table; the two are kept
	/// in lockstep by `tests_catalog::every_catalog_key_appears_in_show_text_with_kind_and_reference`,
	/// so a key added here without listing it slips the test rather than
	/// appearing in `limits show` without the metadata the operator
	/// needs.
	#[allow(dead_code)] // The catalog is the new iteration surface; ALL is kept for direct tests.
	pub(super) const ALL: [Self; 28] = [
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
		Self::MaxMessageSize,
		Self::MaxRecipients,
		Self::MessageMemoryBudget,
		Self::MaxConnectionsPerIp,
		Self::MinDataRate,
		Self::DataRateGrace,
		Self::JunkCommandLimit,
		Self::MaxSessionTime,
		Self::PreauthTimeout,
		Self::MaxMailboxConnectionsPerIp,
		Self::MaxHttpConnections,
		Self::MaxHttpConnectionsPerIp,
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
			Self::MaxMessageSize => "max-message-size",
			Self::MaxRecipients => "max-recipients",
			Self::MessageMemoryBudget => "message-memory-budget",
			Self::MaxConnectionsPerIp => "max-connections-per-ip",
			Self::MinDataRate => "min-data-rate",
			Self::DataRateGrace => "data-rate-grace",
			Self::JunkCommandLimit => "junk-command-limit",
			Self::MaxSessionTime => "max-session-time",
			Self::PreauthTimeout => "preauth-timeout",
			Self::MaxMailboxConnectionsPerIp => "max-mailbox-connections-per-ip",
			Self::MaxHttpConnections => "max-http-connections",
			Self::MaxHttpConnectionsPerIp => "max-http-connections-per-ip",
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
			Self::MaxMessageSize => "max_message_size",
			Self::MaxRecipients => "max_recipients",
			Self::MessageMemoryBudget => "message_memory_budget",
			Self::MaxConnectionsPerIp => "max_connections_per_ip",
			Self::MinDataRate => "min_data_rate",
			Self::DataRateGrace => "data_rate_grace",
			Self::JunkCommandLimit => "junk_command_limit",
			Self::MaxSessionTime => "max_session_time",
			Self::PreauthTimeout => "preauth_timeout",
			Self::MaxMailboxConnectionsPerIp => "max_mailbox_connections_per_ip",
			Self::MaxHttpConnections => "max_http_connections",
			Self::MaxHttpConnectionsPerIp => "max_http_connections_per_ip",
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

	/// Whether a configured `0` turns the limit off, shown as `disabled`.
	pub(super) fn zero_turns_off(self) -> bool {
		matches!(
			self,
			Self::MinDataRate | Self::JunkCommandLimit | Self::MaxSessionTime
		)
	}

	/// Whether a configured `0` means "the default", not "no limit".
	pub(super) fn zero_is_default(self) -> bool {
		matches!(
			self,
			Self::MaxConnectionsPerIp
				| Self::MaxMailboxConnectionsPerIp
				| Self::MaxHttpConnections
				| Self::MaxHttpConnectionsPerIp
		)
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

	/// The least value an Internet standard lets the key take, with the
	/// reason `set` gives when a value goes below it.
	pub(super) fn must_floor(self) -> Option<(u64, &'static str)> {
		match self {
			Self::MaxRecipients => Some((
				crate::smtp::session::MIN_MAX_RECIPIENTS as u64,
				crate::smtp::session::MIN_MAX_RECIPIENTS_REASON,
			)),
			_ => None,
		}
	}

	/// The smallest value the RFC still recommends (SHOULD). A value
	/// below this is accepted with a warning, never refused. The
	/// returned string is the exact one-line warning `epistle limits
	/// set` prints.
	pub(super) fn should_floor(self) -> Option<(u64, &'static str)> {
		match self {
			Self::QueueGiveUp => Some((
				crate::queue::schedule::SHOULD_GIVE_UP_SECS,
				"queue-give-up is below the 4 days RFC 5321 §4.5.4.1 recommends; \
				 recipients will bounce sooner than the standard expects",
			)),
			Self::QueueRetryBase => Some((
				crate::queue::schedule::SHOULD_RETRY_BASE_SECS,
				"queue-retry-base is below the 30 minutes the RFC recommends; \
				 the first retry is sooner than receivers expect",
			)),
			_ => None,
		}
	}

	pub(super) fn unit(self) -> Unit {
		match self {
			Self::Quota | Self::MaxMessageSize | Self::MessageMemoryBudget => Unit::Size,
			Self::MinDataRate => Unit::Rate,
			Self::QueueGiveUp
			| Self::DataRateGrace
			| Self::MaxSessionTime
			| Self::PreauthTimeout
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
			| Self::InboundRatePerSender
			| Self::JunkCommandLimit => u32::MAX as u64,
			Self::MaxConnectionsPerListener | Self::MaxHttpConnections => {
				crate::net::conn_limit::MAX_CONNECTIONS as u64
			}
			Self::MaskedAddressesMax
			| Self::MaxMailboxConnectionsPerIp
			| Self::MaxHttpConnectionsPerIp
			| Self::MaxConnectionsPerIp => (usize::MAX as u64).min(i64::MAX as u64),
			Self::QueueConcurrency | Self::QueuePerDomainConcurrency => {
				crate::queue::limits::MAX_CONCURRENCY as u64
			}
			Self::QueueBackoff => crate::queue::backoff::MAX_STEP_SECS,
			Self::MaxRecipients => crate::smtp::session::MAX_MAX_RECIPIENTS as u64,
			Self::MaxMessageSize | Self::MessageMemoryBudget => i64::MAX as u64,
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
			Self::MaxMessageSize => config.max_message_size.filter(|value| *value != 0),
			Self::MaxRecipients => config.max_recipients.map(|value| value as u64),
			Self::MessageMemoryBudget => config.message_memory_budget,
			Self::MaxConnectionsPerIp => config.max_connections_per_ip.map(|value| value as u64),
			Self::MinDataRate => config.min_data_rate,
			Self::DataRateGrace => config.data_rate_grace,
			Self::JunkCommandLimit => config.junk_command_limit,
			Self::MaxSessionTime => config.max_session_time,
			Self::PreauthTimeout => config.preauth_timeout,
			Self::MaxMailboxConnectionsPerIp => config
				.max_mailbox_connections_per_ip
				.filter(|value| *value != 0)
				.map(|value| value as u64),
			Self::MaxHttpConnections => config
				.max_http_connections
				.filter(|value| *value != 0)
				.map(|value| value as u64),
			Self::MaxHttpConnectionsPerIp => config
				.max_http_connections_per_ip
				.filter(|value| *value != 0)
				.map(|value| value as u64),
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
			Self::MaxMessageSize => Some(crate::smtp::session::MAX_MESSAGE_SIZE as u64),
			Self::MaxRecipients => Some(crate::smtp::session::DEFAULT_MAX_RECIPIENTS as u64),
			Self::MaxConnectionsPerIp => {
				Some(crate::smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP as u64)
			}
			Self::MinDataRate => Some(crate::smtp::server::DEFAULT_MIN_DATA_RATE),
			Self::DataRateGrace => Some(crate::smtp::server::DEFAULT_DATA_RATE_GRACE_SECS),
			Self::JunkCommandLimit => {
				Some(u64::from(crate::smtp::session::DEFAULT_JUNK_COMMAND_LIMIT))
			}
			Self::MaxSessionTime => Some(crate::smtp::server::DEFAULT_MAX_SESSION_TIME_SECS),
			Self::PreauthTimeout => Some(crate::net::deadline::DEFAULT_PREAUTH_TIMEOUT.as_secs()),
			Self::MaxMailboxConnectionsPerIp => {
				Some(crate::net::conn_limit::DEFAULT_MAILBOX_CONNECTIONS_PER_IP as u64)
			}
			Self::MaxHttpConnections => {
				Some(crate::net::conn_limit::DEFAULT_HTTP_CONNECTIONS as u64)
			}
			Self::MaxHttpConnectionsPerIp => {
				Some(crate::net::conn_limit::DEFAULT_HTTP_CONNECTIONS_PER_IP as u64)
			}
			_ => None,
		}
	}
}
