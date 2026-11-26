//! The `--scope` options of `api-key create` and `api-key set`: which names are
//! taken, which of them warn, and which an account-bound key refuses.

use std::process::ExitCode;

use crate::api::api_keys::{ApiKeyStore, Scope, legacy_cutoff};
use crate::config::Config;

/// The names 0.14.0 used that open both management and mail.
const LEGACY_WIDE: [&str; 2] = ["read", "write"];

/// Validate a `--scope` argument. Called by the CLI dispatch before the value
/// reaches `ApiKeyStore::add` (the store repeats the check; this gives the
/// user a clean error before any I/O happens). The seven names are taken, and
/// `read` and `write` still are, with a warning.
pub(in crate::cli) fn parse_scope(value: &str) -> Result<String, String> {
	if value.parse::<Scope>().is_ok() || LEGACY_WIDE.contains(&value) {
		return Ok(value.to_string());
	}
	Err(format!(
		"unknown scope \"{value}\" (expected manage:read, manage:write, mail:read, mail:write, send, scim, alias, ban or health)"
	))
}

/// The warning for a key made with `read` or `write`, which now open both
/// management and mail, or `None` when it holds neither of them. A key bound to
/// one account reaches no management route, so it gets none.
pub(super) fn legacy_warning(scopes: &[String], account_bound: bool) -> Option<String> {
	if account_bound
		|| !scopes
			.iter()
			.any(|name| LEGACY_WIDE.contains(&name.as_str()))
	{
		return None;
	}
	Some(format!(
		"`read` and `write` open both management and mail; use manage:read, manage:write, \
		 mail:read or mail:write (`stack update` refuses a stack that still has one from {})",
		legacy_cutoff::LEGACY_SCOPES_REFUSED_FROM
	))
}

/// Why an account-bound key may not hold what `scopes` names, if it may not:
/// SCIM and the aliases manage accounts from outside, and the management
/// scopes open routes that have no "own account". The first message is the one
/// 0.14.0 gave, kept as it was.
pub(super) fn bound_refusal(scopes: &[String]) -> Option<&'static str> {
	let names = |wanted: &[&str]| scopes.iter().any(|name| wanted.contains(&name.as_str()));
	if names(&["scim", "alias", "ban", "health"]) {
		Some(
			"account-bound API keys cannot hold the scim, alias, ban or health scope (all are administrative)",
		)
	} else if names(&["manage:read", "manage:write"]) {
		Some(
			"account-bound API keys cannot hold the manage:read or manage:write scope (both are administrative)",
		)
	} else {
		None
	}
}

/// The scopes of `row` as an operator reads them: the names 0.15.0 uses when
/// the key has them, the ones it was made with otherwise.
pub(super) fn shown<'a>(scopes: &'a [String], grants: &'a [String]) -> &'a [String] {
	crate::api::api_keys::display_names(scopes, grants)
}

/// `epistle api-key set LABEL --scope S...`: replace the scopes of a key.
pub(super) fn set_scopes(
	config: &Config,
	label: &str,
	scopes: Vec<String>,
	json: bool,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	let mut store = match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => store,
		Err(error) => {
			super::super::style::error(format_args!("opening API key store: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let Some(row) = store.list().into_iter().find(|row| row.label == label) else {
		return super::super::exit::refused(format_args!("no such API key \"{label}\""));
	};
	if row.account.is_some()
		&& let Some(refusal) = bound_refusal(&scopes)
	{
		return super::super::exit::policy(refusal);
	}
	if let Some(warning) = legacy_warning(&scopes, row.account.is_some()) {
		super::super::style::warn_to(err, warning);
	}
	match store.set_scopes(label, &scopes) {
		Ok(()) => {
			let held = store
				.list()
				.into_iter()
				.find(|row| row.label == label)
				.map(|row| shown(&row.scopes, &row.grants).to_vec())
				.unwrap_or_default();
			let mut report = super::super::json_out::Report::new(out, json);
			report.line(format_args!(
				"set scopes {} for API key \"{label}\"",
				held.join(",")
			));
			report.change(
				"set",
				true,
				serde_json::json!({ "label": label, "scopes": held }),
				None,
			)
		}
		Err(error) => {
			let code = super::super::exit::for_io_error(&error);
			super::super::style::error(error);
			code
		}
	}
}
