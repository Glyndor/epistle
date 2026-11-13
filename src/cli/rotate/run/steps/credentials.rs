//! API keys and app passwords: every one gets a new secret.
//!
//! The new secret is kept in the secrets file and its hash in the journal
//! before the store changes. A store write is one atomic rewrite, so after a
//! cut the stored hash is either the old one or the journal's, and the next
//! run applies the journal's hash only when it is not there yet.

use crate::api::ApiKeyStore;
use crate::config::Config;
use crate::directory_store::app_passwords::AppPasswordStore;
use crate::evidence::bindings;

use super::super::journal::{Intent, Kind, Step};
use super::super::secrets::Secrets;

/// Whether the step rotates a row of the API key store.
fn is_api_key(kind: Kind) -> bool {
	matches!(kind, Kind::ApiKey | Kind::PanelApiKey)
}

/// One step per API key and per app password, in label order.
pub(super) fn plan(config: &Config) -> Result<Vec<Step>, String> {
	let keys = ApiKeyStore::open(&config.data_dir)
		.map_err(|error| format!("opening the API key store: {error}"))?;
	let mut steps: Vec<Step> = keys
		.keys()
		.iter()
		.map(|key| Step::pending(Kind::ApiKey, &key.label, None))
		.collect();
	let apps = AppPasswordStore::open(&config.data_dir)
		.map_err(|error| format!("opening the app password store: {error}"))?;
	steps.extend(
		apps.list()
			.into_iter()
			.map(|(account, label, ..)| Step::pending(Kind::AppPassword, &label, Some(&account))),
	);
	Ok(steps)
}

/// Make the new secret, keep it, and say which hash it leaves.
pub(super) fn prepare(
	config: &Config,
	step: &Step,
	secrets: &mut Secrets,
) -> Result<Intent, String> {
	let secret =
		crate::cli::generate_secret().ok_or("the system gave no random bytes for a secret")?;
	let intent = if is_api_key(step.kind) {
		Intent::Replace {
			old: api_key_hash(config, &step.item)?,
			new: crate::api::api_keys::sha256_hash(&secret),
		}
	} else {
		Intent::Replace {
			old: None,
			new: crate::smtp::auth::hash_password(&secret)
				.map_err(|error| format!("cannot hash the secret: {error}"))?,
		}
	};
	secrets.put(step.secret_key(), secret)?;
	Ok(intent)
}

/// Whether the store already holds the hash the step decided on.
pub(super) fn landed(config: &Config, step: &Step, new: &str) -> Result<bool, String> {
	let stored = if is_api_key(step.kind) {
		api_key_hash(config, &step.item)?
	} else {
		app_password_hash(config, step)?
	};
	Ok(stored.as_deref() == Some(new))
}

/// Write the decided hash. For an API key the evidence class follows it: it
/// is bound to the new digest before the store changes and dropped from the
/// old one after, in [`settle`].
pub(super) fn apply(config: &Config, step: &Step, intent: &Intent) -> Result<(), String> {
	let Intent::Replace { old, new } = intent else {
		return Err(format!("{}: the journal records no hash", step.item));
	};
	match step.kind {
		Kind::ApiKey | Kind::PanelApiKey => {
			if let Some(old) = old {
				let (from, to) = (bindings::api_key_key(old), bindings::api_key_key(new));
				bindings::update(&config.data_dir, |bindings| {
					if let Some(class) = bindings.credentials.get(&from).copied() {
						bindings.credentials.insert(to, class);
					}
				})
				.map_err(|error| format!("carrying the class over: {error}"))?;
			}
			let mut store = ApiKeyStore::open(&config.data_dir)
				.map_err(|error| format!("opening the API key store: {error}"))?;
			store
				.rotate(&step.item, new.clone())
				.map_err(|error| format!("API key \"{}\": {error}", step.item))?;
			settle(config, step, intent)
		}
		_ => {
			let owner = step.owner.as_deref().unwrap_or_default();
			let mut store = AppPasswordStore::open(&config.data_dir)
				.map_err(|error| format!("opening the app password store: {error}"))?;
			store
				.rotate(owner, &step.item, new.clone())
				.map_err(|error| format!("app password \"{}\" of {owner}: {error}", step.item))
		}
	}
}

/// What is left once the hash is in place: the old digest's class binding of
/// an API key. Doing it twice is harmless.
pub(super) fn settle(config: &Config, step: &Step, intent: &Intent) -> Result<(), String> {
	let Intent::Replace {
		old: Some(old),
		new,
	} = intent
	else {
		return Ok(());
	};
	if !is_api_key(step.kind) || old == new {
		return Ok(());
	}
	let old = bindings::api_key_key(old);
	bindings::update(&config.data_dir, |bindings| {
		bindings.credentials.remove(&old);
	})
	.map_err(|error| format!("dropping the old class binding: {error}"))
}

fn api_key_hash(config: &Config, label: &str) -> Result<Option<String>, String> {
	let store = ApiKeyStore::open(&config.data_dir)
		.map_err(|error| format!("opening the API key store: {error}"))?;
	Ok(store.hash_of(label))
}

fn app_password_hash(config: &Config, step: &Step) -> Result<Option<String>, String> {
	let store = AppPasswordStore::open(&config.data_dir)
		.map_err(|error| format!("opening the app password store: {error}"))?;
	let owner = step.owner.as_deref().unwrap_or_default();
	Ok(store
		.for_account(owner)
		.iter()
		.find(|app| app.label == step.item)
		.map(|app| app.hash.clone()))
}
