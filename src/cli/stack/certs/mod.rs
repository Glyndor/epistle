//! Turning the certificates container on or off in a stack that runs.
//!
//! The order is what keeps the certificate in service and the ACME account
//! key through a switch that fails halfway:
//!
//! - on: stop `mail`, which can write all of data_dir until it runs with the
//!   split mounts, then check the directories `certs` binds and copy the
//!   key to `secrets/` (the copy under data_dir stays), write the compose
//!   file with `certs`, `podup up -d`, wait for `mail` and for
//!   `certs`, and only then remove the copy under data_dir, which `mail`
//!   could otherwise read. A failure before that writes the previous
//!   compose file back and brings the stack up as it was.
//! - off: copy the key back under data_dir, write the compose file without
//!   `certs`, `podup up -d --remove-orphans` and wait for `mail`. The copy in
//!   `secrets/` is kept; no container but `certs` ever mounted it.
//!
//! `stack rollback` turns it off before it puts an older binary back, since
//! that binary may not know `serve --role`.
//!
//! The compose file is rewritten under the lock that guards it, the same one
//! `stack update`, `stack resources set` and `dns provider set` take, so a
//! rewrite that lands while the switch waits for the lock is read again under
//! it and not lost.

use std::path::Path;

/// Whether the compose file at `compose` runs the certificates container.
/// `Ok(false)` when there is no compose file (a host install). A file that
/// cannot be read or is not the JSON `init` writes is an error, never a
/// "no": the answer decides where the DNS credential and the account key
/// go, and a guess would hand them to `mail`.
pub(in crate::cli) fn runs_certs(compose: &Path) -> Result<bool, String> {
	let Some(bytes) = crate::cli::init::compose_read::read(compose)? else {
		return Ok(false);
	};
	let document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
		format!(
			"{} is not the JSON epistle init writes ({error}); it decides which container \
			 holds the DNS credential, so nothing was changed",
			compose.display()
		)
	})?;
	Ok(document["services"].get("certs").is_some())
}

/// Before `stack up` of a split stack: a copy of the account key left under
/// data_dir, where `mail` reads, is removed (only when `secrets/` holds the
/// same key). A compose file that cannot be read stops `up`.
pub(in crate::cli) fn retire_before_up(data_dir: &Path, compose: &Path) -> Result<(), String> {
	if runs_certs(compose)?
		&& let Some(line) = crate::cli::init::host_secrets::acme::retire_data_dir_copy(data_dir)?
	{
		eprintln!("epistle: {line}");
	}
	Ok(())
}

/// Whether `service` kept running with the same start between two
/// `podup ps --format json` outputs. A container that restarted in between
/// (or stopped) is not up, whatever the second look says.
pub(in crate::cli) fn steady(before: &str, after: &str, service: &str) -> Result<(), String> {
	let started = |json: &str| -> Result<(String, String), String> {
		let rows: Vec<serde_json::Value> =
			serde_json::from_str(json).map_err(|_| "podup ps did not print JSON".to_string())?;
		let row = rows
			.iter()
			.find(|row| row["Service"] == service)
			.ok_or_else(|| format!("podup lists no {service} container"))?;
		Ok((
			row["State"].as_str().unwrap_or_default().to_string(),
			row["StartedAt"].as_str().unwrap_or_default().to_string(),
		))
	};
	let (first, second) = (started(before)?, started(after)?);
	if second.0 == "running" && first == second {
		Ok(())
	} else {
		Err(format!(
			"the {service} container did not stay up (it was {} since {:?}, then {} since {:?}); \
			 `epistle stack logs {service}` says why",
			first.0, first.1, second.0, second.1
		))
	}
}

/// `stack up`: remove a leftover key copy on a split stack, then `podup up
/// -d` and the autostart unit. A layout that cannot be read is reported and
/// `up` goes on: starting the stack is what `up` is for, and the copy is
/// only removed when the file says the split runs.
///
/// The steps run with podup's stderr captured, so the warnings about the
/// ports the stack publishes on purpose can be replaced by one note.
pub(in crate::cli) fn up(
	data_dir: &Path,
	compose: &Path,
	podup: &str,
	published: &mut super::port_warnings::Published,
) -> std::process::ExitCode {
	if let Err(error) = retire_before_up(data_dir, compose) {
		crate::cli::style::warn(format!("no leftover ACME account key was removed: {error}"));
	}
	super::port_warnings::run_steps(
		podup,
		compose,
		&[&["up", "-d"], &["autostart", "install"]],
		published,
	)
}

/// What a switch needs from the host; the tests fake it.
pub(in crate::cli) trait SwitchHost {
	/// The compose file this switch rewrites. The lock beside it guards
	/// the rewrite, so the file is read, rendered and written under it.
	fn compose_path(&self) -> &Path;
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
	/// Where that copy is, for a message that has to name it.
	fn data_dir_key(&self) -> std::path::PathBuf;
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

/// The lock that guards a rewrite of the compose file at `compose`: the
/// one `stack update`, `stack resources set` and `dns provider set` take,
/// so a rewrite of the file never loses the change another writer made.
fn compose_lock(compose: &Path) -> Result<crate::storage::lock::FileLock, String> {
	let lock = crate::storage::locked::lock_path(compose);
	crate::cli::compose::lock::acquire(&lock)
}

/// Bring the stack to the layout `on` names. `Err` says what failed and
/// what was put back.
pub(in crate::cli) fn switch(host: &mut impl SwitchHost, on: bool) -> Result<Switched, String> {
	// The compose file is read, rendered and written under the lock that
	// guards it, so a rewrite that lands while this command waits for the
	// lock is read again under it and not lost: what is written is never a
	// render of a file that has changed since it was read.
	//
	// That lock is taken after the common one, never before it: the caller
	// holds the common lock already (see `stack::entry`), and a command
	// that holds the common lock and waits for this one, and a command that
	// holds this one and waits for the common one, would wait for each
	// other.
	let _held = compose_lock(host.compose_path())?;
	let existing = host.compose_text()?;
	let running =
		serde_json::from_str::<serde_json::Value>(&existing).map_err(|error| {
			format!("compose.yaml is not the JSON epistle init writes: {error}")
		})?["services"]
			.get("certs")
			.is_some();
	if running == on {
		for line in host.place_keys(on)? {
			host.log(&line);
		}
		if on {
			retire(host)?;
		}
		return Ok(Switched::AlreadyThere);
	}
	// Rendered before any key moves: a render that fails leaves nothing to
	// clean up.
	let rendered = host.render(&existing, on)?;
	let mut reached = Reached::Nothing;
	if let Err(error) = bring_up(host, &rendered, on, &mut reached) {
		return Err(put_back(host, &existing, &error, !on, reached));
	}
	if on {
		retire(host)?;
		host.log("the certificates container renews now; mail holds no DNS credential");
	} else {
		host.log("mail renews its certificate again; the certificates container is gone");
	}
	Ok(Switched::Done)
}

/// How far a switch got, which decides what is safe to undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
	/// Nothing of the new layout runs.
	Nothing,
	/// `podup up` of the new layout ran.
	BroughtUp,
}

/// Place the keys, write the new compose file and bring it up, recording
/// in `reached` whether the new layout was started.
fn bring_up(
	host: &mut impl SwitchHost,
	rendered: &str,
	on: bool,
	reached: &mut Reached,
) -> Result<(), String> {
	if on {
		// The running `mail` writes all of data_dir until it is recreated
		// with the split mounts, so it stops before the directories `certs`
		// binds are checked and the key moves: nothing can put a symlink in
		// their place between the check and the bind. A failure from here
		// on brings the previous layout up again, `mail` with it.
		host.podup(&["stop", "mail"])?;
	}
	for line in host.place_keys(on)? {
		host.log(&line);
	}
	host.write_compose(rendered)?;
	host.podup(&["up", "-d", "--remove-orphans"])?;
	*reached = Reached::BroughtUp;
	host.wait_ready("mail")?;
	if on {
		host.wait_ready("certs")?;
	}
	Ok(())
}

fn retire(host: &mut impl SwitchHost) -> Result<(), String> {
	if let Some(line) = host.retire_data_dir_key()? {
		host.log(&line);
	}
	Ok(())
}

/// Write `existing` back and bring the stack up as it was; the message
/// names the failure and whether the stack came back.
///
/// When the layout put back runs `certs` (a failed `disable`), the copy of
/// the account key the switch placed under data_dir has to go, since `mail`
/// mounts it. It is removed whenever the split is what runs: after a
/// successful restore, or when the restore failed but the layout without
/// `certs` was never started. When that layout did start and could not be
/// replaced, `mail` may be renewing with that copy, so it stays and the
/// message names it.
fn put_back(
	host: &mut impl SwitchHost,
	existing: &str,
	error: &str,
	split: bool,
	reached: Reached,
) -> String {
	let restored = host
		.write_compose(existing)
		.and_then(|()| host.podup(&["up", "-d", "--remove-orphans"]));
	let key = host.data_dir_key();
	let restore = match &restored {
		Ok(()) => "the previous compose.yaml was written back and the stack brought up as it was"
			.to_string(),
		Err(again) => format!(
			"writing the previous compose.yaml back failed as well ({again}), so run `epistle \
			 stack up` once the cause is fixed"
		),
	};
	if !split {
		return format!(
			"{error}; {restore}; the ACME account key under data_dir was left in place"
		);
	}
	if restored.is_err() && reached == Reached::BroughtUp {
		return format!(
			"{error}; {restore}; mail runs without the certificates container and may renew \
			 with {}, so it was left there: once the stack is back, delete it, since mail can \
			 read it",
			key.display()
		);
	}
	match host.retire_data_dir_key() {
		Ok(_) => format!(
			"{error}; {restore}; the copy of the ACME account key placed at {} was removed again",
			key.display()
		),
		Err(again) => format!(
			"{error}; {restore}; the copy of the ACME account key at {} could not be removed \
			 ({again}): delete it by hand, mail can read it",
			key.display()
		),
	}
}

mod cli;
pub use cli::CertsCli;
mod host;
pub(in crate::cli) use host::run;

#[cfg(test)]
mod tests;
