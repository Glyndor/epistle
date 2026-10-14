//! The `spool` check: whether `encrypt_at_rest` is on for the spool and
//! whether every file under `<data_dir>/spool/` is currently owner-only.
//!
//! Reading the spool here can read message bodies through the AEAD (so the
//! check works whether or not envelopes are still plaintext being migrated);
//! it never prints one byte of mail content. The check is bounded by the
//! spool size: a linear walk of the spool tree, no recursion into
//! attacker-shaped filenames.

use std::path::Path;

use super::Ctx;
use super::report::{AreaReport, Item, Level};
#[cfg(test)]
use crate::config::Config;
use crate::storage::{FsSpool, MessageCrypto};

/// Check the spool from `ctx`.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let data_dir = config.data_dir.clone();
	let storage = config.storage.clone();
	tokio::task::spawn_blocking(move || evaluate_inner(&data_dir, storage.as_ref()))
		.await
		.unwrap_or_else(|error| AreaReport::fail(format!("spool scan failed: {error}")))
}

/// Probe the spool for the status report without going through the async
/// status harness. Called by the area's tests so they can drive the
/// evaluator directly off a hand-written [`Config`].
#[cfg(test)]
pub(super) fn evaluate(config: &Config) -> AreaReport {
	evaluate_inner(&config.data_dir, config.storage.as_ref())
}

fn evaluate_inner(data_dir: &Path, storage: Option<&crate::config::Storage>) -> AreaReport {
	let crypto = match storage {
		Some(storage) => match MessageCrypto::from_config(Some(storage)) {
			Ok(crypto) => crypto,
			Err(error) => return AreaReport::fail(format!("cannot build spool crypto: {error}")),
		},
		None => MessageCrypto::disabled(),
	};
	let loose = match FsSpool::count_loose_permissions_in(data_dir) {
		Ok(n) => n,
		Err(error) => return AreaReport::fail(format!("spool permission scan failed: {error}")),
	};
	let mut items = vec![
		Item::new(
			"encryption",
			Level::Ok,
			format!("sealed: {}", if crypto.enabled() { "yes" } else { "no" }),
		),
		Item::new(
			"permissions",
			if loose > 0 { Level::Warn } else { Level::Ok },
			format!("loose: {loose}"),
		),
	];
	if loose > 0 {
		items.push(Item::new(
			"spool",
			Level::Warn,
			format!("{loose} spool file(s) or directories have permissions looser than owner-only"),
		));
	}
	let detail = format!(
		"sealed: {}, loose: {loose}",
		if crypto.enabled() { "yes" } else { "no" }
	);
	AreaReport::from_items(items, detail)
}

#[cfg(test)]
#[path = "spool_area_tests.rs"]
mod tests;
