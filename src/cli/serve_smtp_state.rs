//! Per-listener state shared by every SMTP listener (and, where relevant,
//! the IMAP/POP3/API listeners). Pulled out of `serve` because the
//! per-tenant limits, correspondent store, disk-space guard, scanner
//! hook and LLM hook each carried their own multi-line construction and
//! together they were the next-largest block pushing serve.rs past its
//! code-line budget.

use std::sync::Arc;
use std::time::Duration;

use crate::antispam::clamd::ClamdHook;
use crate::antispam::hook::MailHook;
use crate::antispam::llm::LlmHook;
use crate::api::TenantLimits;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::smtp::diskspace::DiskGuard;
use crate::smtp::memory_budget;
use crate::smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP;
use crate::smtp::server::DataRate;
use crate::smtp::server::MemoryBudget;
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
	/// Optional shared byte budget every `DATA` / `BDAT` reservation
	/// draws from. `None` keeps the historical unbounded behaviour; an
	/// operator-set `[server] message_memory_budget` produces a budget
	/// shared by every SMTP listener.
	pub memory_budget: Option<Arc<MemoryBudget>>,
	/// The minimum transfer rate every SMTP listener holds a message
	/// transaction to (`[server] min_data_rate` and `data_rate_grace`).
	pub data_rate: DataRate,
	/// Optional external content scanner hook.
	pub scanner_hook: Option<Arc<dyn MailHook>>,
	/// The clamd client behind `scanner_hook` when clamd is the scanner,
	/// shared with the submission scan so both count and record failures
	/// in one place.
	pub clamd: Option<Arc<ClamdHook>>,
	/// Optional LLM-assisted antispam hook for the uncertain band.
	pub llm_hook: Option<LlmHook>,
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
	// `0` disables the budget (the historical unbounded behaviour) so a
	// configured 0 leaves the slot empty. Any other value becomes a shared
	// budget for every SMTP listener.
	let memory_budget = match config
		.message_memory_budget
		.unwrap_or(memory_budget::DEFAULT_BUDGET_BYTES)
	{
		0 => None,
		cap => {
			// One client gets a quarter of the budget, but always room for
			// one message of the largest size.
			let largest = match max_message_size {
				0 => crate::smtp::session::MAX_MESSAGE_SIZE as u64,
				size => size as u64,
			};
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
		memory_budget,
		data_rate,
		scanner_hook,
		clamd,
		llm_hook,
	})
}

#[cfg(test)]
#[path = "serve_smtp_state_tests.rs"]
mod tests;
