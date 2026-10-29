//! Handlers for `epistle account forward …` and `epistle account catch-all …`.
//!
//! Lives in a sibling so `src/cli/account/mod.rs` and `src/cli/account/actions/mod.rs` stay
//! under the per-file code-line budget. The CLI variants are
//! "list/add/remove" on the resource form; the flat equivalents do not
//! exist (this is the first surface that introduces them).
//!
//! Both surfaces change only the dynamic account store: the static
//! `config::Account` rows keep their `forward`/`catch_all` fields
//! because editing them today is the operator's job against the TOML
//! file. The directory builder at `AccountStore::build_directory`
//! chains dynamic forwards and catch-alls onto the static ones, so a
//! dynamic entry has the same effect at delivery time as an equivalent
//! static one.

use std::io::Write;
use std::process::ExitCode;

use serde_json::json;

use crate::cli::json_out::Report;

use crate::directory_store::{AccountStore, StoreError};

use super::style;

/// List the dynamic account's forward targets, one per line. Static
/// accounts are refused here in the dispatcher with the config-file
/// hint; the handler reads only the dynamic table. A forward to an
/// external delivery destination is one line of opaque text so the
/// operator cannot accidentally sanitise a typo away.
pub(crate) fn forward_list(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let forwards = store.forwards(name);
	for target in &forwards {
		let _ = writeln!(out, "{target}");
	}
	let _ = writeln!(out, "{} forwards", forwards.len());
	ExitCode::SUCCESS
}

/// Add `target` to the dynamic account's forward list. Pass-through to
/// [`AccountStore::add_forward`] for validation: a malformed address,
/// a self-loop onto the account's own addresses, and a duplicate
/// target all keep their typed `StoreError` so the operator sees the
/// exact reason instead of a generic refusal.
pub(crate) fn forward_add_with_store(
	store: &AccountStore,
	name: &str,
	target: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.add_forward(name, target) {
		Ok(()) => {
			let mut report = Report::new(out, json);
			report.line("forward added");
			let fields = json!({ "account": name, "address": target });
			report.change("forward add", true, fields, None)
		}
		Err(error) => forward_catch_all_error(name, "forward", error),
	}
}

/// Drop `target` from the dynamic account's forward list.
pub(crate) fn forward_remove_with_store(
	store: &AccountStore,
	name: &str,
	target: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.remove_forward(name, target) {
		Ok(()) => {
			let mut report = Report::new(out, json);
			report.line("forward removed");
			let fields = json!({ "account": name, "address": target });
			report.change("forward remove", true, fields, None)
		}
		Err(error) => forward_catch_all_error(name, "forward", error),
	}
}

/// List the dynamic account's catch-all domains.
pub(crate) fn catch_all_list(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let domains = store.catch_alls(name);
	for domain in &domains {
		let _ = writeln!(out, "{domain}");
	}
	let _ = writeln!(out, "{} catch-all domains", domains.len());
	ExitCode::SUCCESS
}

/// Add `domain` to the dynamic account's catch-all list. Validated as
/// a configured domain or alias before the lock is taken, so a typo
/// never touches disk.
pub(crate) fn catch_all_add_with_store(
	store: &AccountStore,
	name: &str,
	domain: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.add_catch_all(name, domain) {
		Ok(()) => {
			let mut report = Report::new(out, json);
			report.line("catch-all added");
			let fields = json!({ "account": name, "domain": domain });
			report.change("catch-all add", true, fields, None)
		}
		Err(error) => forward_catch_all_error(name, "catch-all", error),
	}
}

/// Drop `domain` from the dynamic account's catch-all list.
pub(crate) fn catch_all_remove_with_store(
	store: &AccountStore,
	name: &str,
	domain: &str,
	out: &mut dyn Write,
	json: bool,
) -> ExitCode {
	match store.remove_catch_all(name, domain) {
		Ok(()) => {
			let mut report = Report::new(out, json);
			report.line("catch-all removed");
			let fields = json!({ "account": name, "domain": domain });
			report.change("catch-all remove", true, fields, None)
		}
		Err(error) => forward_catch_all_error(name, "catch-all", error),
	}
}

/// Route a forward/catch-all store error to the operator: typed
/// `Invalid` carries the parser-validated reason verbatim, `Duplicate`
/// reads as "already on the list", and a missing account is the same
/// `no such account` message the other mutators print. `kind` is the
/// word the operator typed ("forward" or "catch-all") so the prefix
/// names the surface, not the underlying mutator.
fn forward_catch_all_error(name: &str, kind: &str, error: StoreError) -> ExitCode {
	let code = crate::cli::exit::for_store_error(&error);
	match error {
		StoreError::NotFound(_) => style::error(format_args!("no such account: {name}")),
		StoreError::Invalid(message) => {
			style::error(format_args!("account {name} {kind}: {message}"));
		}
		StoreError::Duplicate(what) => style::error(format_args!(
			"account {name} {kind}: {what} already on the list"
		)),
		other => style::error(format_args!("account {name} {kind}: {other}")),
	}
	code
}
