//! Turning the certificates container on or off in a stack that runs.
//!
//! The order is what keeps the certificate in service and the ACME account
//! key through a switch that fails halfway:
//!
//! - on: copy the key to `secrets/` (the copy under data_dir stays), write
//!   the compose file with `certs`, `podup up -d`, wait for `mail` and for
//!   `certs`, and only then remove the copy under data_dir, which `mail`
//!   could otherwise read. A failure before that writes the previous
//!   compose file back and brings the stack up as it was.
//! - off: copy the key back under data_dir, write the compose file without
//!   `certs`, `podup up -d --remove-orphans` and wait for `mail`. The copy in
//!   `secrets/` is kept; no container but `certs` ever mounted it.
//!
//! `stack rollback` turns it off before it puts an older binary back, since
//! that binary may not know `serve --role`.

use std::path::Path;

/// Whether the compose file at `compose` runs the certificates container.
/// A file that cannot be read or parsed counts as not running it.
pub(in crate::cli) fn runs_certs(compose: &Path) -> bool {
	crate::cli::regular::read::read(compose)
		.ok()
		.and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
		.is_some_and(|document| document["services"].get("certs").is_some())
}

/// What a switch needs from the host; the tests fake it.
pub(in crate::cli) trait SwitchHost {
	/// The compose file as it is now.
	fn compose_text(&mut self) -> Result<String, String>;
	/// `existing` rendered again with the certificates container `on` or off.
	fn render(&mut self, existing: &str, on: bool) -> Result<String, String>;
	/// Put the account key where the layout `on` reads it.
	fn place_keys(&mut self, on: bool) -> Result<Vec<String>, String>;
	/// Replace the compose file.
	fn write_compose(&mut self, text: &str) -> Result<(), String>;
	/// Run one podup step against the compose file on disk.
	fn podup(&mut self, step: &[&str]) -> Result<(), String>;
	/// Wait until `service` is healthy, or runs when it has no healthcheck.
	fn wait_ready(&mut self, service: &str) -> Result<(), String>;
	/// Remove the account key under data_dir once `certs` holds it.
	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String>;
	/// Tell the operator.
	fn log(&mut self, line: &str);
}

/// What a switch did.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::cli) enum Switched {
	/// The stack now runs the layout asked for.
	Done,
	/// It already did; the keys were checked again.
	AlreadyThere,
}

/// Bring the stack to the layout `on` names. `Err` says what failed and
/// what was put back.
pub(in crate::cli) fn switch(host: &mut impl SwitchHost, on: bool) -> Result<Switched, String> {
	let existing = host.compose_text()?;
	let running =
		serde_json::from_str::<serde_json::Value>(&existing).map_err(|error| {
			format!("compose.yaml is not the JSON epistle init writes: {error}")
		})?["services"]
			.get("certs")
			.is_some();
	for line in host.place_keys(on)? {
		host.log(&line);
	}
	if running == on {
		if on {
			retire(host)?;
		}
		return Ok(Switched::AlreadyThere);
	}
	let rendered = host.render(&existing, on)?;
	host.write_compose(&rendered)?;
	let brought_up = host
		.podup(&["up", "-d", "--remove-orphans"])
		.and_then(|()| host.wait_ready("mail"))
		.and_then(|()| if on { host.wait_ready("certs") } else { Ok(()) });
	if let Err(error) = brought_up {
		return Err(put_back(host, &existing, &error));
	}
	if on {
		retire(host)?;
		host.log("the certificates container renews now; mail holds no DNS credential");
	} else {
		host.log("mail renews its certificate again; the certificates container is gone");
	}
	Ok(Switched::Done)
}

fn retire(host: &mut impl SwitchHost) -> Result<(), String> {
	if let Some(line) = host.retire_data_dir_key()? {
		host.log(&line);
	}
	Ok(())
}

/// Write `existing` back and bring the stack up as it was; the message
/// names the failure and whether the stack came back.
fn put_back(host: &mut impl SwitchHost, existing: &str, error: &str) -> String {
	let restored = host
		.write_compose(existing)
		.and_then(|()| host.podup(&["up", "-d", "--remove-orphans"]));
	match restored {
		Ok(()) => format!(
			"{error}; the previous compose.yaml was written back and the stack brought up as it \
			 was, and the ACME account key under data_dir was left in place"
		),
		Err(again) => format!(
			"{error}; writing the previous compose.yaml back failed as well ({again}), so run \
			 `epistle stack up` once the cause is fixed"
		),
	}
}

mod host;
pub(in crate::cli) use host::run;

#[cfg(test)]
mod tests;
