//! `epistle queue destinations` and `epistle queue release-destination`:
//! the recipient domains the outbound queue holds off because they asked it
//! to slow down, why, and lifting such a hold.
//!
//! The worker reads the holds from disk each time it decides whether to
//! contact a destination, so a release takes effect at its next decision,
//! without a restart.

use std::io::Write;
use std::process::ExitCode;

use clap::Args;

use crate::cli::term::sanitize;
use crate::storage::{DestinationHold, FsSpool};

/// One destination by domain, or every held destination with `--all`.
#[derive(Debug, Args)]
pub struct DestinationTarget {
	/// The recipient domain to release.
	#[arg(required_unless_present = "all", conflicts_with = "all")]
	domain: Option<String>,
	/// Release every destination on hold.
	#[arg(long)]
	all: bool,
}

/// The holds still in force at `now`, by domain.
fn active(spool: &FsSpool, now: u64) -> std::io::Result<Vec<(String, DestinationHold)>> {
	Ok(spool
		.load_holds()?
		.into_iter()
		.filter(|(_, hold)| hold.active(now))
		.collect())
}

/// `queue destinations`: every destination on hold, until when, after how
/// many deferrals in a row, and the reply that put it there.
pub(super) fn list(spool: &FsSpool, now: u64, json: bool, out: &mut impl Write) -> ExitCode {
	let held = match active(spool, now) {
		Ok(held) => held,
		Err(error) => return super::fail(format_args!("reading destination holds: {error}")),
	};
	if json {
		let rows: Vec<serde_json::Value> = held
			.iter()
			.map(|(domain, hold)| {
				serde_json::json!({
					"domain": domain,
					"until": hold.until,
					"since": hold.since,
					"deferrals": hold.level.saturating_add(1),
					"reason": hold.reason,
				})
			})
			.collect();
		return crate::cli::json_out::print(out, &serde_json::Value::Array(rows));
	}
	// The domain, an exchanger's name and the reply all come from remote
	// servers: their control characters are shown escaped, never sent to
	// the terminal.
	for (domain, hold) in &held {
		let _ = writeln!(
			out,
			"{}\tuntil={} (in {}s)\tdeferrals={}\treason={}",
			sanitize(domain),
			hold.until,
			hold.until.saturating_sub(now),
			hold.level.saturating_add(1),
			sanitize(&hold.reason)
		);
	}
	let _ = writeln!(out, "{} destinations on hold", held.len());
	ExitCode::SUCCESS
}

/// The line `queue list` adds when destinations are on hold, so the
/// operator sees why their messages wait. `None` when none is.
pub(super) fn summary(spool: &FsSpool, now: u64) -> Option<String> {
	let held = active(spool, now).ok()?;
	if held.is_empty() {
		return None;
	}
	let names: Vec<String> = held.iter().map(|(domain, _)| sanitize(domain)).collect();
	Some(format!(
		"{} destinations on hold: {} (see `epistle queue destinations`)",
		held.len(),
		names.join(", ")
	))
}

/// `queue release-destination`: forget the hold of one destination, or of
/// all, so the queue contacts it again at its next decision. The run of
/// deferrals is forgotten too: a new deferral starts again at the first
/// step.
pub(super) fn release(
	spool: &FsSpool,
	target: &DestinationTarget,
	out: &mut impl Write,
) -> ExitCode {
	let domain = target.domain.as_deref().map(|domain| match domain.trim() {
		// A held sender is named by its account, kept as written.
		sender if sender.starts_with("sender:") => sender.to_string(),
		domain => domain.trim_end_matches('.').to_ascii_lowercase(),
	});
	let mut released = 0usize;
	let written = spool.update_holds(|holds| match &domain {
		Some(domain) => released = usize::from(holds.remove(domain).is_some()),
		None => {
			released = holds.len();
			holds.clear();
		}
	});
	if let Err(error) = written {
		return super::fail(format_args!("writing destination holds: {error}"));
	}
	match domain {
		Some(domain) if released == 0 => crate::cli::exit::refused(format_args!(
			"no destination on hold: {}",
			sanitize(&domain)
		)),
		Some(domain) => {
			let _ = writeln!(out, "released {}", sanitize(&domain));
			ExitCode::SUCCESS
		}
		None => {
			let _ = writeln!(out, "released {released} destinations");
			ExitCode::SUCCESS
		}
	}
}
