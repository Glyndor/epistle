//! Which at-rest key protects an account's new mail, for `account show`.

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::storage::{KeyOwner, MessageCrypto, TenantChoice};

/// The text form: one more line after the rest of `account show`.
pub(super) fn show_line(out: &mut impl std::io::Write, key: &str) {
	let _ = writeln!(out, "encryption_key: {key}");
}

/// The JSON form: the `account show --json` object with `encryption_key`
/// added.
pub(super) fn show_json(
	store: &AccountStore,
	name: &str,
	key: &str,
	out: &mut impl std::io::Write,
) -> std::process::ExitCode {
	let mut plain = Vec::new();
	let code = crate::cli::account::json::show(store, name, &mut plain);
	if code != std::process::ExitCode::SUCCESS {
		return code;
	}
	match serde_json::from_slice::<serde_json::Value>(&plain) {
		Ok(serde_json::Value::Object(mut view)) => {
			view.insert("encryption_key".into(), key.into());
			crate::cli::json_out::print(out, &serde_json::Value::Object(view))
		}
		_ => match out.write_all(&plain) {
			Ok(()) => code,
			Err(_) => std::process::ExitCode::FAILURE,
		},
	}
}

/// One line naming the key new mail of `name` is sealed with and its id,
/// with the reason when a tenant account stays on the server key. Key ids
/// only, never key material.
pub(super) fn describe(config_path: &Path, store: &AccountStore, name: &str) -> String {
	let Ok(config) = Config::load(config_path) else {
		return "unknown: the configuration does not load".into();
	};
	let crypto = match MessageCrypto::from_full_config(&config) {
		Ok(crypto) => crypto,
		Err(error) => return format!("unknown: {error}"),
	};
	crypto.attach_accounts(Arc::new(store.handle()));
	let Some(owner) = crypto.write_owner_for_account(name) else {
		return "none (encrypt_at_rest is off)".into();
	};
	let id = crypto
		.key_listing()
		.into_iter()
		.find(|(candidate, _)| *candidate == owner)
		.map(|(_, id)| id.short())
		.unwrap_or_default();
	let reason = match (crypto.tenant_of_account(name), &owner) {
		(TenantChoice::Partly(tenant), _) => {
			format!("; some addresses are outside tenant \"{tenant}\"")
		}
		(TenantChoice::Several(tenants), _) => {
			format!("; addresses in tenants {}", tenants.join(", "))
		}
		(TenantChoice::One(tenant), KeyOwner::Server) => format!(
			"; tenant \"{tenant}\" has no encryption_key_file or [storage] tenant_keys is off"
		),
		_ => String::new(),
	};
	format!("{owner}, key {id}{reason}")
}

#[cfg(test)]
mod tests;
