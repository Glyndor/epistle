//! The `ports` check: every enabled listener answers with its greeting.

use super::Ctx;
use super::report::{AreaReport, Item, Level};

/// Probe each configured listener the same way `epistle probe` (the mail
/// container's healthcheck) does: its protocol greeting on loopback for a
/// wildcard bind, and on TLS listeners the certificate pinned to the
/// configured file.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	if config.listeners.is_empty() {
		return AreaReport::single(Level::Warn, "no listeners are enabled");
	}
	crate::tls::ensure_crypto_provider();
	let cert = config.tls.as_ref().map(|tls| tls.cert_file.as_path());
	let lines = match crate::cli::probe::probe_all(&config.listeners, cert).await {
		Ok(lines) => lines,
		Err(error) => return AreaReport::fail(format!("cannot probe the listeners: {error}")),
	};
	let items: Vec<Item> = lines
		.into_iter()
		.map(|line| {
			let name = format!("{} {}", line.kind, line.addr);
			match line.error {
				None if line.ok => Item::new(name, Level::Ok, "answers"),
				error => Item::new(name, Level::Fail, error.unwrap_or_default()),
			}
		})
		.collect();
	let answering = items.iter().filter(|item| item.status == Level::Ok).count();
	let summary = format!("{answering} of {} listeners answer", config.listeners.len());
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
#[path = "ports_tests.rs"]
mod tests;
