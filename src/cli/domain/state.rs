//! `epistle domain enable|disable`: switch a hosted domain off without
//! removing it. The switch is the domain's `enabled` field in
//! `<data_dir>/domains.toml`; the server rejects mail for a listed domain like
//! mail for an unknown user and lets nobody send as an address in it.
//! Accounts, mailboxes, aliases and DKIM keys are kept. Its DNS says the same:
//! the null SPF and null MX, a `reject` DMARC policy, and no DKIM or
//! receiving records (see [`crate::dns::skip::DomainRole::Disabled`]).

use super::writers::Commit;
use crate::config::Config;

/// The commit of `domain enable|disable`.
pub(super) fn commit(domain: &str, enabled: bool) -> Commit<'_> {
	let (verb, action) = if enabled {
		("enabled", "enable")
	} else {
		("disabled", "disable")
	};
	Commit {
		subject: format!("domain {domain}"),
		verb,
		already: verb,
		action,
		fields: serde_json::json!({ "domain": domain, "enabled": enabled }),
		records_for: None,
	}
}

/// How many queued messages have an envelope sender in `domain`, or `None`
/// when the queue cannot be read. Capped, so a huge queue costs a bounded
/// scan; the count then reads as at least that many.
pub(super) fn queued_from(config: &Config, domain: &str) -> Option<usize> {
	const SCAN_LIMIT: usize = 100_000;
	let spool =
		crate::storage::FsSpool::open_configured(&config.data_dir, config.storage.as_ref()).ok()?;
	let ids = spool.list().ok()?;
	Some(
		ids.into_iter()
			.take(SCAN_LIMIT)
			.filter_map(|id| spool.load_envelope(id).ok())
			.filter(|envelope| {
				envelope
					.reverse_path
					.rsplit_once('@')
					.is_some_and(|(_, sender)| sender.eq_ignore_ascii_case(domain))
			})
			.count(),
	)
}
