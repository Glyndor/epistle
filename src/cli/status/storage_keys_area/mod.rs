//! The `storage_keys` check: which key protects each tenant's stored mail,
//! whether tenant writes are on, retired server keys still configured, and
//! an unfinished `storage tenant-keys migrate` run.
//!
//! It loads the keys exactly as the server does (so a missing or loose key
//! file fails here first) and prints key ids, never key material. It reads
//! the re-encryption journal and nothing else under `data_dir`.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::config::Config;
use crate::storage::rekey::journal;
use crate::storage::{KeyOwner, MessageCrypto};

/// Check the storage keys from `ctx`.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config.clone(),
		Err(report) => return report,
	};
	tokio::task::spawn_blocking(move || evaluate(&config))
		.await
		.unwrap_or_else(|error| AreaReport::fail(format!("storage key check failed: {error}")))
}

/// Evaluate the storage keys of `config`.
pub(super) fn evaluate(config: &Config) -> AreaReport {
	let crypto = match MessageCrypto::from_full_config(config) {
		Ok(crypto) => crypto,
		Err(error) => return AreaReport::fail(format!("the storage keys do not load: {error}")),
	};
	let listing = crypto.key_listing();
	if listing.is_empty() {
		return AreaReport::ok("no storage key configured");
	}
	let id_of = |owner: &KeyOwner| {
		listing
			.iter()
			.find(|(candidate, _)| candidate == owner)
			.map(|(_, id)| id.short())
	};
	let mut items = Vec::new();
	if let Some(id) = id_of(&KeyOwner::Server) {
		items.push(Item::new("server", Level::Ok, format!("key {id}")));
	}
	let mut keyed = 0;
	for tenant in &config.tenants {
		let Some(name) = &tenant.name else {
			continue;
		};
		let detail = match id_of(&KeyOwner::Tenant(name.clone())) {
			Some(id) => {
				keyed += 1;
				format!("own key {id}")
			}
			None => "the server key (no encryption_key_file)".to_string(),
		};
		items.push(Item::new(format!("tenant {name}"), Level::Ok, detail));
	}
	if keyed > 0 && !crypto.tenant_writes() {
		items.push(Item::new(
			"tenant writes",
			Level::Warn,
			"tenant keys are loaded but [storage] tenant_keys is off: new mail is written under the server key",
		));
	}
	for (owner, id) in &listing {
		if let KeyOwner::Retired(_) = owner {
			items.push(Item::new(
				owner.to_string(),
				Level::Warn,
				format!(
					"key {} is still configured; remove it once `epistle storage tenant-keys migrate` has run and the queue and evidence it sealed are gone",
					id.short()
				),
			));
		}
	}
	match journal::read(&config.data_dir) {
		Ok(None) => {}
		Ok(Some(unfinished)) => items.push(Item::new(
			"re-encryption",
			Level::Warn,
			format!(
				"a {} run of `epistle storage tenant-keys migrate` is unfinished; run it again",
				unfinished.direction
			),
		)),
		Err(error) => items.push(Item::new("re-encryption", Level::Warn, error.to_string())),
	}
	let summary = format!("{} key(s), {keyed} tenant key(s)", listing.len());
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
mod tests;
