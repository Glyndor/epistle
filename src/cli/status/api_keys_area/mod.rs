//! The `api_keys` check: keys that never expire, expire soon or have expired,
//! keys of broad reach, and SCIM keys that name no domain. These are warnings
//! only: no key expires unless the operator gave it an expiry.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope, legacy_cutoff};
use crate::cli::api_keys::expiry::status_warning;

/// Read the same key file as `epistle api-key list`, without a server.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(_) => {
			return AreaReport::single(Level::Warn, "cannot load API keys without configuration");
		}
	};
	match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => evaluate(
			&store,
			&config.data_dir,
			ctx.now
				.duration_since(std::time::UNIX_EPOCH)
				.map_or(0, |elapsed| elapsed.as_secs()),
		),
		Err(_) => AreaReport::single(Level::Warn, "cannot read or parse the API key store"),
	}
}

/// Report each missing, near or past expiry, each key of broad reach, each
/// SCIM key without a domain, and each key whose `--ip-cidr` the container
/// network cannot decide. `now` is epoch seconds.
fn evaluate(store: &ApiKeyStore, data_dir: &std::path::Path, now: u64) -> AreaReport {
	let clause = crate::cli::client::address::hidden_clause(data_dir);
	let mut items = Vec::new();
	for key in store.keys() {
		let scopes = if key.scopes.is_empty() {
			"all (legacy)".to_string()
		} else {
			crate::api::api_keys::display_names(&key.scopes, &key.grants).join(", ")
		};
		let name = format!("{} ({scopes})", key.label);
		match key.expires_at {
			None => items.push(Item::new(&name, Level::Warn, "has no expiry")),
			Some(expires) => {
				if let Some(detail) = status_warning(expires, now) {
					items.push(Item::new(&name, Level::Warn, detail));
				}
			}
		}
		if let Some(detail) = broad_reach(key, clause.is_none()) {
			items.push(Item::new(&name, Level::Warn, detail));
		}
		// `read` and `write` open management and mail at once. The panel's key
		// does so on purpose until the panel has a credential per user.
		if key.label != crate::cli::init::PANEL_KEY_LABEL && key.spans_manage_and_mail() {
			items.push(Item::new(
				&name,
				Level::Warn,
				legacy_cutoff::warning(&key.label),
			));
		}
		// A key that holds one half of `read` or `write` is held too, but that is
		// what every split key is, so only the keys 0.14.0 has no scope for at all
		// are named here; `stack rollback` holds the rest and `docs/api.md` says so.
		let nameless = key
			.reach()
			.is_some_and(|held| crate::api::api_keys::legacy_cover(&held).is_empty());
		if nameless && key.unusable_in_v014() {
			items.push(Item::new(
				&name,
				Level::Warn,
				"0.14.0 cannot preserve this key's permissions: rollback refuses it to prevent broader \
				 access",
			));
		}
		for scope in [Scope::Scim, Scope::Alias] {
			if key.covers_any(&[scope]) && key.reach().is_some() && key.domains.is_empty() {
				items.push(Item::new(
					&name,
					Level::Warn,
					format!("{} key has no associated domain", scope.as_str()),
				));
			}
		}
		if key
			.reach()
			.is_some_and(|held| held.contains(&Scope::Ban) || held.contains(&Scope::Health))
			&& !key.domains.is_empty()
		{
			items.push(Item::new(
				&name,
				Level::Warn,
				"ban or health key is confined to domains, and those routes refuse it: they belong to the whole server",
			));
		}
		if let (Some(cidr), Some(clause)) = (&key.ip_cidr, &clause) {
			items.push(Item::new(
				&name,
				Level::Warn,
				format!(
					"pinned to {cidr}, which is matched against the address the server sees, \
					 and {clause}: it does not see the client address"
				),
			));
		}
	}
	let summary = if items.is_empty() {
		format!("{} keys checked", store.keys().len())
	} else {
		format!("{} API key warnings", items.len())
	};
	AreaReport::from_items(items, summary)
}

/// Why a key reaches further than a leaked copy should: it holds every scope
/// (a legacy key), or it can write or send for every domain from any address.
/// A SCIM key without a domain has its own warning, and a key bound to an
/// account reaches only that account. An `--ip-cidr` confines a key only
/// when the server sees the client address (`cidr_decides`); behind a bridge
/// it does not, and the key counts as unconfined.
fn broad_reach(key: &ApiKey, cidr_decides: bool) -> Option<&'static str> {
	if key.scopes.is_empty() {
		return Some("holds every scope (legacy key); recreate it with explicit --scope");
	}
	let acts = key.reach().is_some_and(|held| {
		held.iter()
			.any(|scope| matches!(scope, Scope::ManageWrite | Scope::MailWrite | Scope::Send))
	});
	(acts
		&& key.domains.is_empty()
		&& key.account.is_none()
		&& !(key.ip_cidr.is_some() && cidr_decides))
		.then_some(
			"can write or send for every domain from any address; confine it with --domain, \
		 --account or --ip-cidr",
		)
}

#[cfg(test)]
mod tests;
