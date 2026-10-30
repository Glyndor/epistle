//! Handlers for `epistle account 2fa show|disable <account>`.
//!
//! Lives in a sibling so the umbrella `src/cli/account/mod.rs` stays under the
//! per-file code-line budget. The store already exposes
//! `AccountStore::set_totp` (cleared via `None`): `disable` is a thin
//! wrapper around that with the same destructive confirmation the
//! other `-remove` actions carry. `show` reports the boolean enrolment
//! and never the secret itself: printing the secret would let anyone
//! with shell history forge codes.

use std::process::ExitCode;

use crate::directory_store::StoreError;

use crate::cli::prompt;
use crate::cli::style;

/// Print whether `name` has a TOTP secret enrolled. Reads the in-memory
/// mirror of the dynamic store; the file watcher keeps that mirror
/// current without needing a restart, and the secret itself is never
/// inspected (the `Option` shape is enough to answer the question).
pub(crate) fn two_factor_show(
	store: &crate::directory_store::AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let Some(account) = store.dynamic_account(name) else {
		return crate::cli::exit::refused(format_args!("no such account: {name}"));
	};
	let enrolled = account.totp_secret.is_some();
	let _ = writeln!(out, "name: {name}");
	let _ = writeln!(out, "enrolled: {}", if enrolled { "yes" } else { "no" });
	ExitCode::SUCCESS
}

/// Drop the TOTP secret on `name`. Carries the destructive-action gate
/// the rest of the umbrella uses (`confirm_destructive`) so an
/// interactive terminal asks, a non-interactive run without `--yes`
/// refuses with exit code 2.
pub(crate) fn two_factor_disable(
	store: &crate::directory_store::AccountStore,
	name: &str,
	yes: bool,
	out: &mut dyn std::io::Write,
	json: bool,
) -> ExitCode {
	let question = format!(
		"Remove TOTP secret for {name}? After this, the password is the only factor. [y/N]"
	);
	if let Err(code) = prompt::confirm_destructive("account 2fa disable", &question, yes) {
		return code;
	}
	match store.set_totp(name, None) {
		Ok(()) => {
			let mut report = crate::cli::json_out::Report::new(out, json);
			report.line("2fa disabled");
			let fields = serde_json::json!({ "account": name, "enrolled": false });
			report.change("2fa disable", true, fields, None)
		}
		Err(error) => {
			let code = crate::cli::exit::for_store_error(&error);
			match error {
				StoreError::NotFound(_) => style::error(format_args!("no such account: {name}")),
				other => style::error(format_args!("account {name}: {other}")),
			}
			code
		}
	}
}
