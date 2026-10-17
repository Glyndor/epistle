//! `--json` output of the `epistle account` reads: `list` and `show`, and
//! the `forward list`, `catch-all list` and `2fa show` sub-actions.
//!
//! A list is an array of objects and a show is one object, with the same
//! keys for a static and a dynamic account so a script never has to branch
//! on the source. Secrets (password hash, SCRAM and TOTP material) never
//! appear.

use std::process::ExitCode;

use serde_json::{Value, json};

use crate::config::{Config, Protocol};
use crate::directory_store::AccountStore;

/// The protocol allowlist: `null` when every protocol may sign in.
pub(crate) fn protocols(allowed: Option<&Vec<Protocol>>) -> Value {
	match allowed {
		None => Value::Null,
		Some(list) => list.iter().map(|protocol| protocol.as_str()).collect(),
	}
}

/// `account list --json`: every account, sorted by name.
pub(crate) fn list(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			super::style::error(format_args!("opening account store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut views = store.account_views();
	views.sort_by(|a, b| a.0.cmp(&b.0));
	let rows = views
		.into_iter()
		.map(|(name, addresses, dynamic)| {
			let source = if dynamic { "dynamic" } else { "static" };
			let display_name = store.display_name(&name);
			json!({
				"name": name,
				"source": source,
				"display_name": display_name,
				"addresses": addresses,
			})
		})
		.collect();
	super::json_out::print(out, &Value::Array(rows))
}

/// `account show --json`: the public view of one account. The caller has
/// already refused an unknown name.
pub(crate) fn show(store: &AccountStore, name: &str, out: &mut impl std::io::Write) -> ExitCode {
	let view = if let Some(account) = store.dynamic(name) {
		json!({
			"name": account.name,
			"log_id": crate::log_id::account(&account.name),
			"source": "dynamic",
			"display_name": account.display_name,
			"addresses": account.addresses,
			"disabled": account.disabled,
			"quota_bytes": account.quota_bytes,
			"protocols": protocols(account.allowed_protocols.as_ref()),
			"two_factor": account.totp_secret.is_some(),
			"forward": account.forward,
			"catch_all": account.catch_all,
		})
	} else if let Some(account) = store.static_view(name) {
		json!({
			"name": account.name,
			"log_id": crate::log_id::account(&account.name),
			"source": "static",
			"display_name": account.display_name,
			"addresses": account.addresses,
			"disabled": false,
			"quota_bytes": account.quota_bytes,
			"protocols": protocols(account.allowed_protocols.as_ref()),
			"two_factor": false,
			"forward": account.forward,
			"catch_all": account.catch_all,
		})
	} else {
		return super::exit::refused(format_args!("no such account: {name}"));
	};
	super::json_out::print(out, &view)
}

/// `account forward list --json`: `[{"address": ...}]`.
pub(crate) fn forwards(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let rows = store
		.forwards(name)
		.into_iter()
		.map(|address| json!({ "address": address }))
		.collect();
	super::json_out::print(out, &Value::Array(rows))
}

/// `account catch-all list --json`: `[{"domain": ...}]`.
pub(crate) fn catch_alls(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let rows = store
		.catch_alls(name)
		.into_iter()
		.map(|domain| json!({ "domain": domain }))
		.collect();
	super::json_out::print(out, &Value::Array(rows))
}

/// `account 2fa show --json`: `{"name": ..., "enrolled": bool}`.
pub(crate) fn two_factor(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let Some(account) = store.dynamic_account(name) else {
		return super::exit::refused(format_args!("no such account: {name}"));
	};
	let view = json!({ "name": name, "enrolled": account.totp_secret.is_some() });
	super::json_out::print(out, &view)
}
