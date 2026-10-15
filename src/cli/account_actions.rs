//! Per-action handlers for `epistle account …`.
//!
//! Lives in a sibling so `account.rs` stays under the per-file code-line
//! budget. Every function takes a pre-built [`AccountStore`] so the test
//! harness can drive the mutators end-to-end without spinning up a
//! real epistle server; the dispatcher in `account::run` opens the
//! store once per call and hands it down here.

use std::io::Write;
use std::process::ExitCode;

use serde_json::json;

use crate::cli::json_out::{Reload, Report};
use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount, StoreError};

use super::style;
use crate::cli::prompt;

/// Pretty rendering of a `DynamicAccount` for `account show`. The
/// fields here are exactly the ones a release / wire operator wants to
/// read; secrets (password hash, SCRAM credentials, TOTP secret) are
/// deliberately omitted.
pub(crate) fn render(account: &DynamicAccount, out: &mut impl std::io::Write) {
	let _ = writeln!(out, "name: {}", account.name);
	let _ = writeln!(out, "log_id: {}", crate::log_id::account(&account.name));
	let _ = writeln!(out, "source: dynamic");
	let _ = writeln!(
		out,
		"display_name: {}",
		shown(account.display_name.as_deref())
	);
	let _ = writeln!(out, "addresses: {}", account.addresses.join(","));
	let _ = writeln!(
		out,
		"disabled: {}",
		if account.disabled { "yes" } else { "no" }
	);
	let quota = match account.quota_bytes {
		Some(bytes) => bytes.to_string(),
		None => "server default".to_string(),
	};
	let _ = writeln!(out, "quota_bytes: {quota}");
	let _ = writeln!(
		out,
		"protocols: {}",
		render_protocols(account.allowed_protocols.as_ref())
	);
	let _ = writeln!(out, "forwards: {}", render_targets(&account.forward));
	let _ = writeln!(out, "catch_all: {}", render_targets(&account.catch_all));
	let _ = writeln!(
		out,
		"two_factor: {}",
		if account.totp_secret.is_some() {
			"yes"
		} else {
			"no"
		}
	);
}

/// Render a one-per-line list with `(none)` for the empty case. The
/// form mirrors the rest of `account show` so a script that greps for
/// `forwards: outside@example.com` keeps matching regardless of
/// whether the account is static or dynamic.
fn render_targets(targets: &[String]) -> String {
	if targets.is_empty() {
		"(none)".to_string()
	} else {
		targets.join(",")
	}
}

/// A display name for `account show`, or `unset`.
fn shown(display_name: Option<&str>) -> &str {
	display_name.unwrap_or("unset")
}

/// `account set-name`: set or (with an empty name) clear the display name.
pub(crate) fn set_name_with_store(
	store: &AccountStore,
	name: &str,
	raw: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	let mut report = Report::new(out, json);
	match store.set_display_name(name, raw) {
		Ok(stored) => {
			match &stored {
				Some(stored) => {
					report.line(format_args!("display name of {name} set to \"{stored}\""))
				}
				None => report.line(format_args!("display name of {name} cleared")),
			}
			let fields = json!({ "account": name, "display_name": stored });
			report.change("set-name", true, fields, None)
		}
		Err(error) => handle_error(name, error),
	}
}

/// Wait for the running server to load the accounts file the store
/// just wrote; see [`crate::cli::account_reload::wait_after_write`].
/// The store holds no lock once its mutator has returned.
fn wait_after_write(store: &AccountStore) -> Reload {
	Reload::from(crate::cli::account_reload::wait(
		store.store_path(),
		&mut style::stderr(),
	))
}

/// Render the protocol allowlist. `None` is the pre-restriction
/// behaviour (every protocol authenticates); an empty list is the
/// "no protocol authenticates" case the SCIM `set protocols []`
/// path produces.
pub(crate) fn render_protocols(allowed: Option<&Vec<Protocol>>) -> String {
	match allowed {
		None => "all".to_string(),
		Some(list) if list.is_empty() => "none".to_string(),
		Some(list) => list
			.iter()
			.map(|protocol| protocol.as_str())
			.collect::<Vec<_>>()
			.join(","),
	}
}

/// Update the password for a dynamic account using the given store and
/// password reader. Splits the dispatcher from the CLI glue so tests
/// can drive the password flow without touching stdin.
///
/// On a terminal the password is typed twice with echo off and a mismatch
/// is refused before any hashing; piped stdin gives one line. The
/// dispatcher calls this only after [`crate::cli::account::prepare`] has
/// confirmed the account exists, so nobody types a password for a name
/// that is not there.
pub(crate) fn password_with_store(
	store: &AccountStore,
	name: &str,
	mut reader: impl std::io::BufRead,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	// let-else for the same reason as `accounts::add`: no value may flow
	// from a diverging arm into the binding the hash reads.
	// `new_password` has printed why it refused (no input, mismatch, or
	// the policy rule that failed): the input is rejected, exit code 2.
	let Some(plain) = prompt::new_password(&format!("Password for \"{name}\""), &mut reader) else {
		return ExitCode::from(crate::cli::exit::REFUSED);
	};
	// Apply the runtime password policy once: the hashed bytes and the SCRAM
	// verifier must be derived from the same canonical form, so a SCRAM-SHA-256
	// client that ran SASLprep on its candidate matches the verifier we
	// stored. With the ASCII-only policy the prepare step is a no-op.
	let prepared = match store.password_policy().prepare(&plain) {
		Ok(prepared) => prepared,
		Err(rejection) => {
			style::error(format_args!(
				"account {name}: {rejection}",
				rejection = rejection.message()
			));
			return ExitCode::FAILURE;
		}
	};
	let hash = match crate::smtp::auth::hash_password(prepared.as_ref()) {
		Ok(hash) => hash,
		Err(error) => {
			style::error(format_args!("account {name}: {error}"));
			return ExitCode::FAILURE;
		}
	};
	// `[auth] scram = false` produces `None` so the mutator drops an existing
	// verifier. With SCRAM on, derivation must not fail (CSPRNG). Failures
	// here abort the password update rather than silently skip the verifier.
	let scram = if store.scram_enabled() {
		match crate::smtp::scram::ScramStored::with_fresh_salt(prepared.as_ref()) {
			Some(scram) => Some(scram),
			None => {
				style::error(format_args!("account {name}: cannot derive SCRAM salt"));
				return ExitCode::FAILURE;
			}
		}
	} else {
		None
	};
	match store.set_password_hash(name, hash, scram) {
		Ok(()) => {
			let mut report = Report::new(out, json);
			report.line("password updated");
			let reload = wait_after_write(store);
			report.change("password", true, json!({ "account": name }), Some(reload))
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn disable_with_store(
	store: &AccountStore,
	name: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	set_disabled(store, name, true, Report::new(out, json))
}

pub(crate) fn enable_with_store(
	store: &AccountStore,
	name: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	set_disabled(store, name, false, Report::new(out, json))
}

/// `account disable` and `account enable`: the store returns the previous
/// state, so a second run reports `unchanged`.
fn set_disabled(store: &AccountStore, name: &str, disabled: bool, mut report: Report) -> ExitCode {
	match store.set_disabled(name, disabled) {
		Ok(previous) => {
			let (action, done) = if disabled {
				("disable", "disabled")
			} else {
				("enable", "enabled")
			};
			let changed = previous != disabled;
			if changed {
				report.line(format_args!("account {done}"));
			} else {
				report.line(format_args!("account already {done}"));
			}
			let reload = wait_after_write(store);
			let fields = json!({ "account": name, "disabled": disabled });
			report.change(action, changed, fields, Some(reload))
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn address_add_with_store(
	store: &AccountStore,
	name: &str,
	address: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.add_address(name, address) {
		Ok(()) => address_changed(Report::new(out, json), "add", name, address),
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn address_remove_with_store(
	store: &AccountStore,
	name: &str,
	address: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.remove_address(name, address) {
		Ok(()) => address_changed(Report::new(out, json), "remove", name, address),
		Err(error) => handle_error(name, error),
	}
}

/// The result of `account address add|remove`.
fn address_changed(mut report: Report, verb: &str, name: &str, address: &str) -> ExitCode {
	report.line(format_args!(
		"address {verb}{}",
		if verb == "add" { "ed" } else { "d" }
	));
	let fields = json!({ "account": name, "address": address });
	report.change(&format!("address {verb}"), true, fields, None)
}

/// The confirmation after a quota change.
pub(crate) fn quota_changed(new: Option<u64>) -> String {
	match new {
		Some(bytes) => format!("quota set to {bytes}"),
		None => "quota set to server default".to_string(),
	}
}

/// The confirmation after a protocol allowlist change.
pub(crate) fn protocols_changed(new: Option<&Vec<Protocol>>) -> String {
	format!("protocols set to {}", render_protocols(new))
}

pub(crate) fn quota_with_store(
	store: &AccountStore,
	name: &str,
	size: Option<u64>,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.set_quota_bytes(name, size) {
		Ok(_) => {
			let mut report = Report::new(out, json);
			report.line(quota_changed(size));
			let fields = json!({ "account": name, "quota_bytes": size });
			report.change("quota", true, fields, None)
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn protocols_with_store(
	store: &AccountStore,
	name: &str,
	allowed: Option<Vec<Protocol>>,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.set_allowed_protocols(name, allowed.clone()) {
		Ok(_) => {
			let mut report = Report::new(out, json);
			report.line(protocols_changed(allowed.as_ref()));
			let names = crate::cli::account_json::protocols(allowed.as_ref());
			let fields = json!({ "account": name, "protocols": names });
			report.change("protocols", true, fields, None)
		}
		Err(error) => handle_error(name, error),
	}
}

/// Confirmation printed after the save-sent toggle.
pub(crate) fn save_sent_changed(value: bool) -> String {
	format!("save_sent set to {}", if value { "on" } else { "off" })
}

/// Toggle the account-wide `save_sent` preference. Static accounts
/// carry no field; the CLI refuses them with the same hint as the
/// other mutators.
pub(crate) fn save_sent_with_store(
	store: &AccountStore,
	name: &str,
	value: bool,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.set_save_sent(name, value) {
		Ok(_) => {
			let mut report = Report::new(out, json);
			report.line(save_sent_changed(value));
			let fields = json!({ "account": name, "save_sent": value });
			report.change("save-sent", true, fields, None)
		}
		Err(error) => handle_error(name, error),
	}
}

/// Print the name of every account whose log pseudonym is `id`. A login
/// that was an address (SMTP and IMAP clients often present one) is
/// pseudonymised as a whole, so an account also matches when one of its
/// addresses does. A miss prints nothing and fails.
pub(crate) fn find_log_id_with_store(
	store: &AccountStore,
	id: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	let id = id.trim().to_ascii_lowercase();
	let mut views = store.account_views();
	views.sort_by(|a, b| a.0.cmp(&b.0));
	let found: Vec<&String> = views
		.iter()
		.filter(|(name, addresses, _)| {
			crate::log_id::account(name) == id
				|| addresses
					.iter()
					.any(|address| crate::log_id::account(address) == id)
		})
		.map(|(name, _, _)| name)
		.collect();
	if found.is_empty() {
		return crate::cli::exit::refused("no account matches that log id on this server");
	}
	let mut report = Report::new(out, json);
	for name in &found {
		report.line(name);
	}
	report.object(json!({ "log_id": id, "accounts": found }))
}

pub(crate) fn show_with_store(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if let Some(account) = store.dynamic(name) {
		render(&account, out);
		return ExitCode::SUCCESS;
	}
	if let Some(account) = store.static_view(name) {
		render_static(account, out);
		return ExitCode::SUCCESS;
	}
	crate::cli::exit::refused(format_args!("no such account: {name}"))
}

/// Public view of a static `[accounts]` row. The shape mirrors the
/// dynamic view so an operator can grep a single set of fields
/// regardless of where the account lives; a static account is
/// `disabled: no` by definition (the loader never sets it) and
/// `two_factor: no` (TOTP is dynamic-only). The password hash is
/// never printed (matches the dynamic viewer's contract).
fn render_static(account: &crate::config::Account, out: &mut impl std::io::Write) {
	let _ = writeln!(out, "name: {}", account.name);
	let _ = writeln!(out, "log_id: {}", crate::log_id::account(&account.name));
	let _ = writeln!(out, "source: static");
	let _ = writeln!(
		out,
		"display_name: {}",
		shown(account.display_name.as_deref())
	);
	let _ = writeln!(out, "addresses: {}", account.addresses.join(","));
	let _ = writeln!(out, "disabled: no");
	let quota = match account.quota_bytes {
		Some(bytes) => bytes.to_string(),
		None => "server default".to_string(),
	};
	let _ = writeln!(out, "quota_bytes: {quota}");
	let _ = writeln!(
		out,
		"protocols: {}",
		render_protocols(account.allowed_protocols.as_ref())
	);
	let _ = writeln!(out, "forwards: {}", render_targets(&account.forward));
	let _ = writeln!(out, "catch_all: {}", render_targets(&account.catch_all));
	let _ = writeln!(out, "two_factor: no");
}

/// Convert a store error into the exit code plus the message the
/// operator sees on stderr. `NotFound` means the name is unknown: a static
/// account is refused with the config-file hint by
/// [`crate::cli::account::prepare`] before it reaches a mutator, so this
/// path prints `no such account`.
pub(crate) fn handle_error(name: &str, error: StoreError) -> ExitCode {
	let code = crate::cli::exit::for_store_error(&error);
	match error {
		StoreError::NotFound(_) => style::error(format_args!("no such account: {name}")),
		StoreError::Duplicate(what) => {
			style::error(format_args!("account {name}: {what} already exists"));
		}
		StoreError::Invalid(message) => style::error(format_args!("account {name}: {message}")),
		other => style::error(format_args!("account {name}: {other}")),
	}
	code
}

/// Parse the `on`/`off` switch the `save_sent` and quota
/// subcommands accept. Kept here so `account.rs` can re-export the
/// parser without keeping the whole table of accepted spellings
/// in two places; the rules live once, callers see a short
/// signature.
pub(crate) fn parse_on_off(raw: &str) -> Result<bool, String> {
	let trimmed = raw.trim();
	match trimmed.to_ascii_lowercase().as_str() {
		"on" => Ok(true),
		"off" => Ok(false),
		other => Err(format!("expected `on` or `off`, got {other:?}")),
	}
}

/// Parse a single protocol name. Duplicates the kebab-case
/// spellings the TOML `Protocol` deserialiser already understands
/// so the CLI list and the config file spell them the same way.
pub(crate) fn parse_protocol_inner(name: &str) -> Result<Protocol, String> {
	match name.to_ascii_lowercase().as_str() {
		"smtp" => Ok(Protocol::Smtp),
		"submission" => Ok(Protocol::Submission),
		"submissions" => Ok(Protocol::Submissions),
		"api" => Ok(Protocol::Api),
		"imap" => Ok(Protocol::Imap),
		"imaps" => Ok(Protocol::Imaps),
		"pop3s" => Ok(Protocol::Pop3s),
		"managesieve" => Ok(Protocol::ManageSieve),
		"webdav" => Ok(Protocol::WebDav),
		other => Err(format!(
			"unknown protocol {other:?} (expected smtp, submission, submissions, api, imap, imaps, pop3s, managesieve, webdav or 'all')"
		)),
	}
}

/// Parse a protocol-list argument (`imap,smtp`, `all`). Unknown
/// protocol names are rejected with a list of the accepted ones so a
/// typo never reaches the store. `all` (case-insensitive) returns
/// `Ok(None)` to clear the restriction.
pub(crate) fn parse_protocol_list_inner(raw: &str) -> Result<Option<Vec<Protocol>>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("protocol list is empty (expected imap,smtp or 'all')".to_string());
	}
	if trimmed.eq_ignore_ascii_case("all") {
		return Ok(None);
	}
	let mut out = Vec::new();
	for token in trimmed.split(',') {
		let name = token.trim();
		if name.is_empty() {
			return Err("protocol list has an empty entry".to_string());
		}
		let protocol = parse_protocol_inner(name)?;
		if !out.contains(&protocol) {
			out.push(protocol);
		}
	}
	Ok(Some(out))
}

#[cfg(test)]
#[path = "cli_account_save_sent_tests.rs"]
mod save_sent_tests;
#[cfg(test)]
#[path = "account_actions_show_fields_tests.rs"]
mod show_fields_tests;
