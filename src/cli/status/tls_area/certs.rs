//! The certificates container, when the stack runs one: whether it runs,
//! and what its absence means for the certificate `mail` presents.
//!
//! With `certs` down nothing renews: `mail` keeps serving the certificate it
//! has until it expires, so the item names the container's state and the
//! days the certificate has left, and fails when those days are few.

use std::path::Path;

use super::super::report::{Item, Level};
use super::{DAY, FAIL_DAYS, plural};

/// The state podup reports for the `certs` container, `None` when podup
/// lists none: it lists running containers only, so a stopped one is `None`
/// too. `Err` when podup could not be asked or answered with something that
/// is not its JSON.
pub(super) fn state(podup: &str, compose: &Path) -> Result<Option<String>, String> {
	let json = crate::cli::stack::started::ps_json_with(
		podup,
		compose,
		crate::cli::stack::started::PS_TIMEOUT,
	)?;
	state_in(&json)
}

/// [`state`] read from the output of `podup ps --format json`.
pub(super) fn state_in(json: &str) -> Result<Option<String>, String> {
	let rows: Vec<serde_json::Value> = serde_json::from_str(json)
		.map_err(|_| "podup ps did not print the JSON it prints".to_string())?;
	Ok(rows
		.iter()
		.find(|row| row["Service"] == "certs")
		.map(|row| row["State"].as_str().unwrap_or("unknown").to_string()))
}

/// The item for the certificates container in `state`, with `remaining`
/// seconds left on the certificate in service.
pub(super) fn item(state: &Result<Option<String>, String>, remaining: i64) -> Item {
	let left = if remaining > 0 {
		format!("{} left", plural(remaining / DAY))
	} else {
		"already expired".to_string()
	};
	let (seen, running) = match state {
		Ok(Some(state)) if state == "running" => (String::new(), true),
		Ok(Some(state)) => (format!("is {state}"), false),
		Ok(None) => ("is not running".to_string(), false),
		Err(error) => (format!("could not be read ({error})"), false),
	};
	if running {
		return Item::new(
			"certs",
			Level::Ok,
			format!("the certificates container renews the certificate; {left}"),
		);
	}
	let level = if remaining < FAIL_DAYS * DAY {
		Level::Fail
	} else {
		Level::Warn
	};
	Item::new(
		"certs",
		level,
		format!(
			"the certificates container {seen}, so nothing renews: mail serves the certificate it \
			 has, {left}; `epistle stack up` starts it"
		),
	)
}

/// With the certificates container DKIM rotation waits: it publishes
/// through the credential `mail` no longer holds, and moves to `certs` in a
/// later step.
pub(super) fn dkim_item() -> Item {
	Item::new(
		"dkim rotation",
		Level::Warn,
		"DKIM keys do not rotate while the certificates container holds the DNS credential; the \
		 key in use keeps signing",
	)
}
