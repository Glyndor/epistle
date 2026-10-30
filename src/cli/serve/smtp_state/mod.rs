//! Per-listener state shared by every SMTP listener (and, where relevant,
//! the IMAP/POP3/API listeners). Pulled out of `serve` because the
//! per-tenant limits, correspondent store, disk-space guard, scanner
//! hook and LLM hook each carried their own multi-line construction and
//! together they were the next-largest block pushing src/cli/serve/mod.rs past its
//! code-line budget.

use std::sync::Arc;
use std::time::Duration;

use crate::antispam::attachments::policy::Policy;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::hook::MailHook;
use crate::antispam::llm::LlmHook;
use crate::api::TenantLimits;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::smtp::diskspace::DiskGuard;
use crate::smtp::memory_budget;
use crate::smtp::memory_fit;
use crate::smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP;
use crate::smtp::server::DataRate;
use crate::smtp::server::MemoryBudget;
use crate::smtp::server::SessionLimits;
use crate::storage::CorrespondentStore;

/// Everything `serve` attaches to every SMTP listener that comes from
/// server-wide config: tenant limits, correspondent store, daily
/// new-recipient cap, shared disk guard, per-listener concurrency cap,
/// and the optional antispam hooks. A fresh struct is built once at
/// startup; the same values are then cloned or borrowed by every
/// listener arm in the loop below.
pub(super) struct SmtpSharedState {
	/// Per-tenant aggregate limits; an empty list makes every check a no-op.
	pub tenant_limits: Arc<TenantLimits>,
	/// Per-account correspondent store (one `Arc` shared by every SMTP
	/// listener and the API state).
	pub correspondents: Arc<CorrespondentStore>,
	/// Per-account rolling 24h cap on first-time recipients.
	pub daily_new_recipients: Option<u32>,
	/// Shared disk-space guard for `data_dir` (`MAIL FROM` rejects with
	/// `452` when the spool cannot hold another message).
	pub disk_guard: Arc<DiskGuard>,
	/// Per-listener concurrency cap; `0` keeps each protocol's built-in
	/// default.
	pub max_conn: usize,
	/// Per-IP concurrency cap (default [`DEFAULT_MAX_CONNECTIONS_PER_IP`]).
	/// `0` keeps the built-in default.
	pub max_connections_per_ip: usize,
	/// Per-instance message-size cap in bytes. `0` keeps the SMTP
	/// session's built-in default ([`crate::smtp::session::MAX_MESSAGE_SIZE`]).
	pub max_message_size: usize,
	/// Recipients one message may name (`max_recipients`), on every SMTP
	/// listener, the REST send endpoint and JMAP submission.
	pub max_recipients: usize,
	/// Optional shared byte budget every `DATA` / `BDAT` reservation
	/// draws from, shared by every SMTP listener: `[server]
	/// message_memory_budget`, or when unset the one derived from the mail
	/// container's memory limit. `None` when it is set to `0`.
	pub memory_budget: Option<Arc<MemoryBudget>>,
	/// The minimum transfer rate every SMTP listener holds a message
	/// transaction to (`[server] min_data_rate` and `data_rate_grace`).
	pub data_rate: DataRate,
	/// The junk-command limit and session lifetime of every SMTP listener
	/// (`[server] junk_command_limit` and `max_session_time`).
	pub session_limits: SessionLimits,
	/// Optional external content scanner hook.
	pub scanner_hook: Option<Arc<dyn MailHook>>,
	/// The clamd client behind `scanner_hook` when clamd is the scanner,
	/// shared with the submission scan so both count and record failures
	/// in one place.
	pub clamd: Option<Arc<ClamdHook>>,
	/// Optional LLM-assisted antispam hook for the uncertain band.
	pub llm_hook: Option<LlmHook>,
	/// The `[attachments]` policy, shared by every SMTP listener and the
	/// submission sink; `None` when `mode = "off"`.
	pub attachment_policy: Option<Arc<Policy>>,
}

/// Build the per-listener shared state. A missing or unreachable data
/// directory for the correspondent store fails closed (a fatal startup
/// error); a malformed scanner-hook URL also fails closed; the LLM
/// hook is built eagerly so a missing API key stops the start before
/// the first mail that hits the uncertain band.
pub(super) fn build_smtp_shared_state(
	config: &Config,
	metrics: &Arc<Metrics>,
) -> std::io::Result<SmtpSharedState> {
	let limit = memory_fit::container_limit(&memory_fit::LimitPaths::system(&config.data_dir));
	build_smtp_shared_state_with(config, metrics, limit)
}

/// [`build_smtp_shared_state`] with the mail container's memory limit
/// given, so the tests never read the host's cgroup.
pub(super) fn build_smtp_shared_state_with(
	config: &Config,
	metrics: &Arc<Metrics>,
	limit: memory_fit::ContainerLimit,
) -> std::io::Result<SmtpSharedState> {
	let tenant_limits = Arc::new(TenantLimits::from_config(&config.tenants));
	let correspondents =
		Arc::new(CorrespondentStore::open(&config.data_dir).map_err(std::io::Error::other)?);
	let daily_new_recipients = config.new_recipients_per_day;
	let disk_guard = Arc::new(DiskGuard::new(config.data_dir.clone()));
	let max_conn = config.max_connections_per_listener.unwrap_or(0);
	let max_connections_per_ip = config.max_connections_per_ip.unwrap_or(0);
	let max_message_size = config
		.max_message_size
		.map(|value| value as usize)
		.unwrap_or(0);
	let largest = match max_message_size {
		0 => crate::smtp::session::MAX_MESSAGE_SIZE as u64,
		size => size as u64,
	};
	// An unset budget follows the memory the mail container may use; a
	// configured one is kept, with a warning when it does not fit.
	let budget = memory_fit::effective(config.message_memory_budget, largest, limit);
	if let Some(warning) = memory_fit::warning(&budget) {
		tracing::warn!("{warning}");
	} else if budget.derived {
		tracing::info!(
			budget_mib = memory_fit::mib(budget.bytes),
			limit_mib = memory_fit::mib(limit.bytes),
			limit_source = limit.source.describe(),
			"message memory budget derived from the mail container's memory limit"
		);
	}
	// `0` disables the budget (the historical unbounded behaviour) so a
	// configured 0 leaves the slot empty. Any other value becomes a shared
	// budget for every SMTP listener.
	let memory_budget = match budget.bytes {
		0 => None,
		cap => {
			// One client gets a quarter of the budget, but always room for
			// one message of the largest size.
			let share = (cap / memory_budget::CLIENT_SHARE_DIVISOR).max(largest);
			Some(Arc::new(
				memory_budget::MemoryBudget::with_cap(cap).with_client_share(share),
			))
		}
	};
	let clamd = config.antispam.clamd_socket.as_ref().map(|socket| {
		Arc::new(
			ClamdHook::new(socket.clone())
				.with_on_found(config.antispam.clamd_on_found.into())
				.with_on_error(config.antispam.clamd_on_error)
				.with_timeout(Duration::from_secs(config.antispam.clamd_timeout_secs))
				.with_max_bytes(config.antispam.clamd_max_bytes)
				.with_metrics(Arc::clone(metrics))
				.with_health_file(&config.data_dir),
		)
	});
	let scanner_hook: Option<Arc<dyn MailHook>> = match &config.scanner_hook_url {
		Some(url) => Some(Arc::new(
			crate::antispam::hook::HttpHook::new(url).map_err(std::io::Error::other)?,
		)),
		None => clamd.clone().map(|clamd| clamd as Arc<dyn MailHook>),
	};
	let llm_hook = LlmHook::from_config(config.antispam_llm.as_ref())?;
	// Absent keys keep the built-in floor and grace; a configured 0 floor
	// is forwarded as is and turns the check off.
	let data_rate = DataRate::new(
		config
			.min_data_rate
			.unwrap_or(crate::smtp::server::DEFAULT_MIN_DATA_RATE),
		Duration::from_secs(
			config
				.data_rate_grace
				.unwrap_or(crate::smtp::server::DEFAULT_DATA_RATE_GRACE_SECS),
		),
	);
	// No message is larger than the size limit, so no inspection decodes
	// more than that.
	let decode_limit = match max_message_size {
		0 => crate::smtp::session::MAX_MESSAGE_SIZE,
		size => size,
	};
	let attachment_policy = Policy::from_config(&config.attachments, decode_limit).map(Arc::new);
	// A configured 0 on the per-IP cap means "use the protocol default",
	// not "0 concurrent connections per peer". When the operator omits the
	// key the listener keeps its built-in default; an explicit 0 falls back
	// the same way.
	let max_connections_per_ip = if max_connections_per_ip == 0 {
		DEFAULT_MAX_CONNECTIONS_PER_IP
	} else {
		max_connections_per_ip
	};
	Ok(SmtpSharedState {
		tenant_limits,
		correspondents,
		daily_new_recipients,
		disk_guard,
		max_conn,
		max_connections_per_ip,
		max_message_size,
		max_recipients: config
			.max_recipients
			.unwrap_or(crate::smtp::session::DEFAULT_MAX_RECIPIENTS),
		memory_budget,
		data_rate,
		session_limits: session_limits(config),
		scanner_hook,
		clamd,
		llm_hook,
		attachment_policy,
	})
}

/// The session limits of every SMTP listener: absent keys keep the
/// built-in ones, a configured 0 is forwarded as is and turns that limit
/// off. Validation has already bounded both.
fn session_limits(config: &Config) -> SessionLimits {
	let built_in = SessionLimits::default();
	SessionLimits {
		junk_commands: config
			.junk_command_limit
			.map_or(built_in.junk_commands, |limit| {
				u32::try_from(limit).unwrap_or(u32::MAX)
			}),
		max_session_time: config
			.max_session_time
			.map_or(built_in.max_session_time, Duration::from_secs),
	}
}

#[cfg(test)]
mod tests;
