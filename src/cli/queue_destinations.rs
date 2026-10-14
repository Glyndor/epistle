//! `epistle queue destinations` and `epistle queue release-destination`:
//! the destinations (recipient domains and exchanger hosts) the outbound
//! queue holds off because they asked it to slow down, why, and lifting
//! such a hold.
//!
//! The holds are read from the spool, where the recipients that wait for
//! them keep their next attempt (see [`crate::queue::backoff`]). A release
//! makes those recipients due at once and starts their backoff over; the
//! running worker reads it at its next scan.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::ExitCode;

use clap::Args;

use crate::cli::term::sanitize;
use crate::queue::backoff::{Hold, Holds};
use crate::queue::destination::{Destination, Kind};
use crate::storage::{FsSpool, RecipientStatus};

/// One destination by name, or every held destination with `--all`.
#[derive(Debug, Args)]
pub struct DestinationTarget {
	/// The recipient domain or exchanger host to release.
	#[arg(required_unless_present = "all", conflicts_with = "all")]
	domain: Option<String>,
	/// Release every destination on hold.
	#[arg(long)]
	all: bool,
}

/// The holds in force at `now`, by destination.
fn in_force(spool: &FsSpool, now: u64) -> std::io::Result<Vec<(Destination, Hold)>> {
	let holds = Holds::read(spool)?;
	Ok(holds
		.in_force(now)
		.into_iter()
		.map(|(destination, hold)| (destination.clone(), hold.clone()))
		.collect())
}

/// `queue destinations`: every destination on hold, until when, after how
/// many deferrals in a row, and the reply that put it there.
pub(super) fn list(spool: &FsSpool, now: u64, json: bool, out: &mut impl Write) -> ExitCode {
	let held = match in_force(spool, now) {
		Ok(held) => held,
		Err(error) => return super::fail(format_args!("reading the spool: {error}")),
	};
	if json {
		let rows: Vec<serde_json::Value> = held
			.iter()
			.map(|(destination, hold)| {
				serde_json::json!({
					"kind": destination.kind().label(),
					"name": destination.as_str(),
					"until": hold.until,
					"deferrals": hold.deferrals,
					"reason": hold.reason,
				})
			})
			.collect();
		return crate::cli::json_out::print(out, &serde_json::Value::Array(rows));
	}
	// The name and the reply come from remote servers: their control
	// characters are shown escaped, never sent to the terminal.
	for (destination, hold) in &held {
		let _ = writeln!(
			out,
			"{} {}\tuntil={} (in {}s)\tdeferrals={}\treason={}",
			destination.kind().label(),
			sanitize(destination.as_str()),
			hold.until,
			hold.until.saturating_sub(now),
			hold.deferrals,
			sanitize(&hold.reason)
		);
	}
	let _ = writeln!(out, "{} destinations on hold", held.len());
	ExitCode::SUCCESS
}

/// The line `queue list` adds when destinations are on hold, so the
/// operator sees why their messages wait. `None` when none is.
pub(super) fn summary(spool: &FsSpool, now: u64) -> Option<String> {
	let held = in_force(spool, now).ok()?;
	if held.is_empty() {
		return None;
	}
	let names: Vec<String> = held
		.iter()
		.map(|(destination, _)| {
			format!(
				"{} {}",
				destination.kind().label(),
				sanitize(destination.as_str())
			)
		})
		.collect();
	Some(format!(
		"{} destinations on hold: {} (see `epistle queue destinations`)",
		held.len(),
		names.join(", ")
	))
}

/// The exchangers on hold at `now`, and the time it is.
type HeldExchangers = (Vec<Destination>, u64);

/// The destination whose hold `recipient` of `envelope` waits for, when it
/// is `wanted` (or any, without `wanted`): the one that asked it to slow
/// down, or, for a recipient whose own domain never did, the exchanger on
/// hold it was passed over at.
fn released_by(
	envelope: &crate::storage::Envelope,
	recipient: &str,
	wanted: Option<&(Destination, Destination)>,
	(exchangers, now): &HeldExchangers,
) -> Option<Destination> {
	let state = envelope.recipient_state(recipient);
	if state.status != RecipientStatus::Pending {
		return None;
	}
	if state.throttled == 0 {
		let host = state
			.remote
			.as_deref()
			.map(Destination::exchanger)
			.filter(|host| state.next_attempt > *now && exchangers.contains(host))?;
		return match wanted {
			Some((_, wanted)) if *wanted != host => None,
			_ => Some(host),
		};
	}
	let domain = Destination::of_recipient(recipient);
	let host = state.remote.as_deref().map(Destination::exchanger);
	match wanted {
		None => Some(domain),
		Some((wanted, _)) if *wanted == domain => Some(domain),
		Some((_, wanted)) if host.as_ref() == Some(wanted) => host,
		Some(_) => None,
	}
}

/// `queue release-destination`: make every recipient waiting for the hold
/// of one destination (or of all, with `--all`) due now, and start its
/// backoff over.
pub(super) fn release(
	spool: &FsSpool,
	target: &DestinationTarget,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	// A name given on the command line may be a domain or an exchanger:
	// the holds of both kinds under that name are released.
	let wanted = target
		.domain
		.as_deref()
		.map(|name| (Destination::domain(name), Destination::exchanger(name)));
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => return super::fail(format_args!("reading the spool: {error}")),
	};
	let exchangers = match in_force(spool, now) {
		Ok(held) => held
			.into_iter()
			.map(|(destination, _)| destination)
			.filter(|destination| destination.kind() == Kind::Exchanger)
			.collect(),
		Err(error) => return super::fail(format_args!("reading the spool: {error}")),
	};
	let held = (exchangers, now);
	let mut released: BTreeSet<Destination> = BTreeSet::new();
	for id in ids {
		// Only entries with a recipient waiting for the hold are written.
		let waits = spool.load_envelope(id).is_ok_and(|envelope| {
			envelope.recipients.iter().any(|recipient| {
				released_by(&envelope, recipient, wanted.as_ref(), &held).is_some()
			})
		});
		if !waits {
			continue;
		}
		let edited = spool.update_envelope(id, |envelope| {
			for recipient in envelope.recipients.clone() {
				let Some(matched) = released_by(envelope, &recipient, wanted.as_ref(), &held)
				else {
					continue;
				};
				released.insert(matched);
				let mut state = envelope.recipient_state(&recipient);
				state.throttled = 0;
				state.next_attempt = now;
				envelope.set_recipient_state(&recipient, state);
			}
			envelope.settle();
		});
		match edited {
			Ok(_) => {}
			// The worker delivered or dropped it since the listing.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return super::fail(format_args!("queue entry {id}: {error}")),
		}
	}
	match wanted {
		Some((wanted, _)) if released.is_empty() => crate::cli::exit::refused(format_args!(
			"no destination on hold: {}",
			sanitize(wanted.as_str())
		)),
		Some((wanted, _)) => {
			let _ = writeln!(out, "released {}", sanitize(wanted.as_str()));
			ExitCode::SUCCESS
		}
		None => {
			let _ = writeln!(out, "released {} destinations", released.len());
			ExitCode::SUCCESS
		}
	}
}
