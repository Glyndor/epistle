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
	/// Optional external content scanner hook.
	pub scanner_hook: Option<Arc<dyn MailHook>>,
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
	let scanner_hook: Option<Arc<dyn MailHook>> = match &config.scanner_hook_url {
		Some(url) => Some(Arc::new(
			crate::antispam::hook::HttpHook::new(url).map_err(std::io::Error::other)?,
		)),
		None => config.antispam.clamd_socket.as_ref().map(|socket| {
			Arc::new(
				ClamdHook::new(socket.clone())
					.with_on_found(config.antispam.clamd_on_found.into())
					.with_timeout(Duration::from_secs(config.antispam.clamd_timeout_secs))
					.with_max_bytes(config.antispam.clamd_max_bytes)
					.with_metrics(Arc::clone(metrics)),
			) as Arc<dyn MailHook>
		}),
	};
	let llm_hook = LlmHook::from_config(config.antispam_llm.as_ref())?;
	Ok(SmtpSharedState {
		tenant_limits,
		correspondents,
		daily_new_recipients,
		disk_guard,
		max_conn,
		scanner_hook,
		llm_hook,
	})
}

#[cfg(test)]
#[path = "serve_smtp_state_tests.rs"]
mod tests;
