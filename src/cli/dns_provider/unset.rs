//! `dns provider unset --zone`: remove one zone's entry and keep the rest.
//!
//! The entry leaves with its credential. The generated compose file mounts
//! the token file of each entry and forwards its variable, so the removed
//! entry's mount and variable go too, unless another entry still reads them.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use toml_edit::TableLike;

use crate::cli::config_edit::{
	ConfigDocument, Outcome, after_credential_change_reporting, commit_pair,
};
use crate::cli::resource::{self, ResourceError};
use crate::cli::stack::StackAction;
use crate::config::Config;

/// Remove the `[dns]` entry for `zone` from the configuration and its
/// credential from the container. Refuses when there is no such entry, so a
/// typo never reports a removal that did not happen.
pub(super) fn run(
	path: &Path,
	zone: &str,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	let zone = resource::dns_name("--zone", zone)?;
	let _held = if dry_run {
		None
	} else {
		Some(crate::cli::service::lock::acquire(path)?)
	};
	let mut document = ConfigDocument::open(path)?;
	let current = document.config()?;
	let dropped: Vec<&str> = current
		.dns
		.for_zone(&zone)
		.and_then(|dns| dns.token_env.as_deref())
		.into_iter()
		.collect();
	remove(&mut document, &zone)?;
	let config = document.config()?;
	// The generated compose file is rewritten through the companion, so it
	// is read and written under the lock that guards it. The common lock
	// above was taken first and this one after it, in every command that
	// takes both, so no two commands wait for each other.
	let compose_lock = if dry_run {
		None
	} else {
		super::compose::lock_compose(&current)?
	};
	let compose = super::compose::with_token(&current, &zone, None, &dropped)?;
	// The services whose definition the compose change touches: each one of
	// them has to be recreated, or its container keeps the mount it had.
	let touched: Vec<&'static str> = compose
		.update
		.as_ref()
		.map(|update| update.changed.clone())
		.unwrap_or_default();
	// The override the operator keeps beside the generated file can hand
	// the credential back to the container the split took it away from, and
	// nothing in the generated file says so.
	for warning in &compose.warnings {
		crate::cli::style::warn_to(status, format_args!("{warning}"));
	}
	let edit = resource::Edit {
		label: "dns provider",
		action: "provider unset",
		fields: serde_json::json!({ "zone": zone }),
		json,
	};
	if dry_run {
		let change = compose
			.update
			.as_ref()
			.map(|update| resource::CompanionChange {
				companion: &update.companion,
				lines: &update.lines,
			});
		return resource::preview(&document, change, &edit, out);
	}
	let outcome = commit_pair(document, compose.update.map(|update| update.companion))
		.map_err(ResourceError::from)?;
	// The generated file is written, so the lock that guarded it is free
	// again: a command that waits for it does not wait for the container
	// this one recreates.
	drop(compose_lock);
	let changed = outcome == Outcome::Changed;
	writeln!(
		status,
		"dns provider {}",
		if changed { "saved" } else { "unchanged" }
	)
	.map_err(|error| error.to_string())?;
	let (code, reload) =
		after_credential_change_reporting(&config, outcome, status, restart, &touched)?;
	if json {
		let object =
			crate::cli::json_out::change_object(edit.action, changed, edit.fields, Some(reload));
		writeln!(out, "{object}").map_err(|error| error.to_string())?;
	}
	Ok(code)
}

/// Remove the entry for `zone` from the document, or say there is none.
fn remove(document: &mut ConfigDocument, zone: &str) -> Result<(), String> {
	let removed = if document.is_table("dns") {
		// A lone `[dns]` table is the entry of its own zone.
		let owns = document.config()?.dns.for_zone(zone).is_some();
		if owns {
			document.remove_table(&["dns"])?;
		}
		usize::from(owns)
	} else {
		document.remove_where("dns", &|table: &dyn TableLike| {
			super::write::is_zone(table, zone)
		})?
	};
	if removed == 0 {
		return Err(format!("no [dns] entry for zone {zone}"));
	}
	Ok(())
}
