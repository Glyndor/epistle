//! The `ports` check: every enabled listener answers with its greeting.

use super::Ctx;
use super::report::{AreaReport, Item, Level};

/// Probe each configured listener the same way `epistle probe` (the mail
/// container's healthcheck) does, using published host bindings outside the
/// container and keeping the configured certificate pin for TLS listeners.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	if config.listeners.is_empty() {
		return AreaReport::single(Level::Warn, "no listeners are enabled");
	}
	crate::tls::ensure_crypto_provider();
	let served = crate::tls::served_tls(config);
	let cert = served.as_ref().map(|served| served.tls.cert_file.as_path());
	let lines = match crate::cli::probe::published::probe(config, cert, &ctx.podup).await {
		Ok(lines) => lines,
		Err(error) => return AreaReport::fail(format!("cannot probe the listeners: {error}")),
	};
	report(lines, config.listeners.len())
}

fn report(lines: Vec<crate::cli::probe::ProbeLine>, total: usize) -> AreaReport {
	let items: Vec<Item> = lines
		.into_iter()
		.map(|line| {
			let name = format!("{} {}", line.kind, line.addr);
			if let Some(warning) = line.warning {
				return Item::new(name, Level::Warn, warning);
			}
			match line.error {
				None if line.ok => Item::new(name, Level::Ok, "answers"),
				error => Item::new(name, Level::Fail, error.unwrap_or_default()),
			}
		})
		.collect();
	let answering = items.iter().filter(|item| item.status == Level::Ok).count();
	let mut summary = format!("{answering} of {total} listeners answer");
	let unchecked = items
		.iter()
		.filter(|item| item.status == Level::Warn)
		.count();
	if unchecked > 0 {
		summary.push_str(&format!(
			"; {unchecked} not checkable from here, inspect published ports with `epistle stack ps --json`"
		));
	}
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
mod tests;
