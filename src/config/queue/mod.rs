//! Outbound queue configuration: the `[queue]` section.
//!
//! `outbound_tls` selects how the STARTTLS certificate of a recipient MX is
//! authenticated; its default is the most restrictive option (strict PKIX
//! verification), so an absent `[queue]` section leaves existing deployments
//! unchanged (fail closed). `tlsrpt_reports` turns the outbound TLS-RPT
//! reports off, `dmarc_reports` the outbound DMARC aggregate reports, and
//! `dmarc_report_from` says which address they come from.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::queue::limits::GroupLimit;
use crate::queue::warmup::Group;

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

/// Which list an automatic suppression is written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionScope {
	/// The list every sender shares.
	Server,
	/// The list of the sender's tenant, which every domain of the tenant reads.
	Tenant,
	/// The list of the sending account alone.
	Account,
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
	/// Record the DMARC verdict of every inbound message and send the
	/// daily DMARC aggregate report (RFC 7489) to every domain that asks
	/// for one. Defaults to `true`.
	#[serde(default = "default_dmarc_reports")]
	pub dmarc_reports: bool,
	/// Address the DMARC aggregate reports are sent from, and the contact
	/// the report XML names. Absent uses `postmaster@<hostname>`.
	#[serde(default)]
	pub dmarc_report_from: Option<String>,
	/// Outbound conversations running at once, all destinations together.
	/// Defaults to [`crate::queue::limits::DEFAULT_CONCURRENCY`].
	#[serde(default = "default_concurrency")]
	pub concurrency: usize,
	/// Outbound conversations running at once with any one recipient domain.
	/// Defaults to [`crate::queue::limits::DEFAULT_PER_DOMAIN_CONCURRENCY`].
	#[serde(default = "default_per_domain_concurrency")]
	pub per_domain_concurrency: usize,
	/// Outbound conversations running at once with any one receiver group:
	/// the provider behind the exchangers of the recipient domains. A
	/// group with no entry is not limited. Absent leaves every group as
	/// it was.
	#[serde(default)]
	pub per_group_concurrency: BTreeMap<Group, GroupLimit>,
	/// How long a destination that asks to slow down is held off, in
	/// seconds, one step per deferral in a row, the last repeating.
	/// Defaults to [`crate::queue::backoff::DEFAULT_STEPS`].
	#[serde(default = "default_backoff_steps")]
	pub backoff_steps: Vec<u64>,
	/// Minimum pause for provider rate limits, in seconds (default 600).
	#[serde(default = "default_provider_pause_secs")]
	pub provider_pause_secs: u64,
	/// The lists a permanent bounce that proves an address bad suppresses it
	/// in: any of `account`, `tenant` and `server`. Default `["account",
	/// "tenant"]`, so one customer's typo does not block the others. Entries
	/// added by hand are never affected, and a block is checked in every list.
	#[serde(default = "default_suppression_scopes")]
	pub suppression_scopes: Vec<SuppressionScope>,
	/// Days an automatic suppression lasts before the address is tried again,
	/// and the window in which bounces are counted. Default `0`: for ever.
	#[serde(default)]
	pub suppression_days: u64,
	/// Permanent bounces of mail from one sender to one address before it is
	/// suppressed. Default `1`: the first one does.
	#[serde(default = "default_suppression_threshold")]
	pub suppression_threshold: u32,
}

fn default_suppression_scopes() -> Vec<SuppressionScope> {
	vec![SuppressionScope::Account, SuppressionScope::Tenant]
}

const fn default_suppression_threshold() -> u32 {
	1
}

const fn default_provider_pause_secs() -> u64 {
	crate::queue::backoff::DEFAULT_PROVIDER_PAUSE_SECS
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

const fn default_dmarc_reports() -> bool {
	true
}

impl Default for Queue {
	fn default() -> Self {
		Queue {
			outbound_tls: OutboundTls::default(),
			tlsrpt_reports: default_tlsrpt_reports(),
			dmarc_reports: default_dmarc_reports(),
			dmarc_report_from: None,
			concurrency: default_concurrency(),
			per_domain_concurrency: default_per_domain_concurrency(),
			per_group_concurrency: BTreeMap::new(),
			backoff_steps: default_backoff_steps(),
			provider_pause_secs: default_provider_pause_secs(),
			suppression_scopes: default_suppression_scopes(),
			suppression_days: 0,
			suppression_threshold: default_suppression_threshold(),
		}
	}
}

impl super::Config {
	/// The address the DMARC aggregate reports come from: the one the
	/// operator configured, or `postmaster@<hostname>` when the setting is
	/// absent.
	pub fn dmarc_report_from(&self) -> String {
		self.queue
			.dmarc_report_from
			.clone()
			.unwrap_or_else(|| format!("postmaster@{}", self.hostname))
	}

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
		if !(1..=crate::queue::backoff::MAX_STEP_SECS).contains(&queue.provider_pause_secs) {
			return invalid(
				"[queue] provider_pause_secs must be between 1 and 86400 seconds".into(),
			);
		}
		self.validate_per_group_concurrency()?;
		self.validate_backoff_steps()
	}

	/// The limits of the receiver groups must make sense: a group may not
	/// have more conversations at once than the queue runs altogether, and
	/// its wait between two connections is bounded like a backoff step.
	fn validate_per_group_concurrency(&self) -> Result<(), super::ConfigError> {
		use crate::queue::limits::MAX_GROUP_WAIT_SECS;
		let queue = &self.queue;
		let invalid = |message: String| Err(super::ConfigError::Invalid(message));
		for (group, limit) in &queue.per_group_concurrency {
			// `other` is every receiver that is none of the named providers:
			// unrelated domains, not one queue, so it cannot share a limit.
			if *group == Group::Other {
				return invalid(
					"[queue] per_group_concurrency cannot limit `other`: it is every receiver \
					 that is not a named provider, not one queue"
						.to_string(),
				);
			}
			if !(1..=queue.concurrency).contains(&limit.concurrency) {
				return invalid(format!(
					"[queue] per_group_concurrency.{group} concurrency must be between 1 and \
					 concurrency ({}) (got {})",
					queue.concurrency, limit.concurrency
				));
			}
			if limit.min_wait_secs > MAX_GROUP_WAIT_SECS {
				return invalid(format!(
					"[queue] per_group_concurrency.{group} min_wait_secs must be between 0 and \
					 {MAX_GROUP_WAIT_SECS} seconds (got {})",
					limit.min_wait_secs
				));
			}
		}
		Ok(())
	}

	/// The address the DMARC reports come from must be one plain mailbox
	/// with a valid domain name: the value goes into the `From:` header of
	/// a message we sign, so anything that could break out of that header
	/// is refused rather than escaped. The refused value is quoted escaped,
	/// so a CR or LF in it cannot forge a log line either.
	pub(in crate::config) fn validate_dmarc_report_from(&self) -> Result<(), super::ConfigError> {
		let Some(address) = &self.queue.dmarc_report_from else {
			return Ok(());
		};
		let invalid = |message: String| Err(super::ConfigError::Invalid(message));
		let Some((_, domain)) = crate::util::address::plain_mailbox(address) else {
			return invalid(format!(
				"[queue] dmarc_report_from {address:?} is not a plain mailbox (local@domain)"
			));
		};
		super::validate_dns_name("[queue] dmarc_report_from domain", domain)?;
		Ok(())
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
	/// the give-up window closes. The conversation caps and the backoff of
	/// the `[queue]` section are checked with it.
	pub(super) fn validate_suppression(&self) -> Result<(), super::ConfigError> {
		let queue = &self.queue;
		let invalid =
			|message: &str| Err(super::ConfigError::Invalid(format!("[queue] {message}")));
		if queue.suppression_scopes.is_empty() {
			return invalid("suppression_scopes needs at least one of account, tenant, server");
		}
		let scopes = &queue.suppression_scopes;
		if (1..scopes.len()).any(|at| scopes[..at].contains(&scopes[at])) {
			return invalid("suppression_scopes names a scope twice");
		}
		if !(1..=100).contains(&queue.suppression_threshold) {
			return invalid("suppression_threshold must be between 1 and 100");
		}
		if queue.suppression_days > 36_500 {
			return invalid("suppression_days must be at most 36500");
		}
		Ok(())
	}

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
		self.validate_queue_limits()
	}

	/// SHOULD warnings: a value the RFC recommends but does not require.
	/// The validation above refuses values that break the protocol
	/// invariants; the warnings here flag values that still work but
	/// deviate from the recommendation. `epistle limits set` and the
	/// start-up banner print the same lines.
	pub fn retry_schedule_warnings(&self) -> Vec<String> {
		use crate::queue::schedule::{
			DEFAULT_BASE_SECS, DEFAULT_GIVE_UP_SECS, SHOULD_GIVE_UP_SECS, SHOULD_RETRY_BASE_SECS,
		};
		let give_up = self
			.queue_give_up_secs
			.filter(|secs| *secs != 0)
			.unwrap_or(DEFAULT_GIVE_UP_SECS);
		// Only a value the operator set counts: the default is a short
		// first retry on purpose (a first temporary failure such as
		// greylisting), so running on it is not a deviation to report.
		let base = self
			.queue_retry_base_secs
			.filter(|secs| *secs != 0 && *secs != DEFAULT_BASE_SECS);
		let mut warnings = Vec::new();
		if give_up < SHOULD_GIVE_UP_SECS {
			warnings.push(
				"queue_give_up_secs is below the 4 days RFC 5321 §4.5.4.1 recommends; \
				 recipients will bounce sooner than the standard expects"
					.to_owned(),
			);
		}
		if let Some(base) = base.filter(|base| *base < SHOULD_RETRY_BASE_SECS) {
			warnings.push(format!(
				"queue_retry_base_secs is {base} seconds, below the {SHOULD_RETRY_BASE_SECS} \
				 seconds (30 minutes) the RFC recommends; the first retry is sooner than \
				 receivers expect (the default is {DEFAULT_BASE_SECS} seconds)"
			));
		}
		warnings
	}
}

#[cfg(test)]
mod tests;
