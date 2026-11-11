//! `epistle account set <name> --send on|off --receive on|off`.
//!
//! The two switches say what the account may do with mail, independently of
//! `account disable` (sign-in) and of `account protocols` (which protocols
//! may sign in), so the four combinations exist: a normal mailbox,
//! receive-only, send-only (the application senders) and an account that does
//! neither but still exists, for example one that only keeps an alias.

use std::process::ExitCode;

use serde_json::json;

use crate::cli::json_out::{Reload, Report};
use crate::cli::style;
use crate::directory_store::{AccountStore, Switch};

/// The state of the account's two switches as the words `account show`
/// prints: `on` or `off`.
pub(crate) fn word(on: bool) -> &'static str {
	if on { "on" } else { "off" }
}

/// Apply the switches that were given to the account `name` and report them.
/// A switch left out keeps its state. A second identical run reports
/// `unchanged`.
pub(super) fn set(
	store: &AccountStore,
	name: &str,
	send: Option<bool>,
	receive: Option<bool>,
	out: &mut dyn std::io::Write,
	json: bool,
) -> ExitCode {
	let mut changed = false;
	for (switch, wanted) in [(Switch::Send, send), (Switch::Receive, receive)] {
		let Some(on) = wanted else { continue };
		match store.set_switch(name, switch, on) {
			Ok(previous) => changed |= previous != on,
			Err(error) => return super::handle_error(name, error),
		}
	}
	let (send_now, receive_now) = store.switches(name);
	let mut report = Report::new(out, json);
	report.line(format_args!(
		"send {}, receive {}",
		word(send_now),
		word(receive_now)
	));
	let reload = if changed {
		Reload::from(crate::cli::account::reload::wait(
			store.store_path(),
			&mut style::stderr(),
		))
	} else {
		Reload::None
	};
	let fields = json!({ "account": name, "send": send_now, "receive": receive_now });
	report.change("set", changed, fields, Some(reload))
}

/// Parse the `on`/`off` value of `--send` or `--receive`, refusing anything
/// else before the store is opened.
pub(super) fn parse(name: &str, flag: &str, raw: Option<&str>) -> Result<Option<bool>, ExitCode> {
	let Some(raw) = raw else { return Ok(None) };
	super::parse_on_off(raw).map(Some).map_err(|error| {
		crate::cli::exit::refused(format_args!("account {name}: --{flag}: {error}"))
	})
}

#[cfg(test)]
mod tests;
