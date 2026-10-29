//! `mail suppression`: view or edit the outbound suppression list (addresses
//! that hard-bounced and are no longer delivered to).

use std::process::ExitCode;

use std::path::PathBuf;

use clap::Subcommand;

use crate::config::Config;
use crate::queue::SuppressionList;

#[path = "suppression_exchange.rs"]
mod exchange;

/// Actions on the outbound suppression list (`epistle suppression
/// list|add|remove`).
#[derive(Debug, Subcommand)]
pub enum SuppressionCli {
	/// Print every suppressed address, one per line.
	///
	/// A hard bounce also gives when it happened and the remote reply, tab
	/// separated after the address. With `--account`, list that sending
	/// account's per-account list instead of the global one.
	List {
		/// Restrict the list to this sending account.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Print a JSON array of `{"address", "account", "since", "reason"}`
		/// objects (`since` and `reason` are null when not recorded).
		#[arg(long)]
		json: bool,
	},
	/// Stop delivering to an address.
	///
	/// Mail queued for it is dropped without a bounce, as after a hard
	/// bounce.
	Add {
		/// Recipient address to suppress.
		address: String,
		/// Suppress it for this sending account only, not for everyone.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Why it is suppressed, kept with the entry (at most 512 characters,
		/// no control characters). Defaults to a note that it was added by hand.
		#[arg(long, value_name = "TEXT")]
		reason: Option<String>,
		/// Print the result as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
	/// Resume delivering to an address.
	///
	/// Drops the suppression marker, from the global list or, with
	/// `--account`, from that sender's list.
	Remove {
		/// Recipient address to resume delivering to.
		address: String,
		/// Remove the per-account suppression for this sender only.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Print the result as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
	/// Show one suppressed address with when and why.
	///
	/// Exits 2 when the address is not suppressed in that list.
	Show {
		/// The address to show.
		address: String,
		/// Look in this sending account's list instead of the global one.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Print the entry as one JSON object.
		#[arg(long)]
		json: bool,
	},
	/// Write the list as CSV: address, when, why.
	///
	/// The output is a header line `address,since,reason` and one entry per
	/// line, in the form `suppression import` reads.
	Export {
		/// Export this sending account's list instead of the global one.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Print one JSON array of `{"address", "since", "reason"}` objects
		/// instead of CSV.
		#[arg(long)]
		json: bool,
	},
	/// Suppress every address of a file.
	///
	/// The file is UTF-8 text, at most 16 MiB and 100000 entries: one entry
	/// per line as `address`, or `address,since,reason` with the time in
	/// RFC 3339 UTC (the form `suppression export` writes). Blank lines and
	/// lines starting with `#` are skipped. The file is checked whole first:
	/// one bad line refuses it and nothing is written. An address that is
	/// already suppressed keeps its entry.
	Import {
		/// The file to read.
		file: PathBuf,
		/// Import into this sending account's list instead of the global one.
		#[arg(long, value_name = "ACCOUNT", value_parser = crate::cli::account::name::parse)]
		account: Option<String>,
		/// Reason for the lines that carry none (at most 512 characters, no
		/// control characters).
		#[arg(long, value_name = "TEXT")]
		reason: Option<String>,
		/// Count what would be added and write nothing.
		#[arg(long)]
		dry_run: bool,
		/// Print the result as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
}

impl SuppressionCli {
	/// The action to run for a command line whose `--json` came before the
	/// action, or with no action at all: `address_to_remove` and `account`
	/// are the older flat forms, which list or remove when no action is
	/// named.
	pub(super) fn with_json(
		action: Option<Self>,
		json: bool,
		address_to_remove: Option<String>,
		account: Option<String>,
	) -> Option<Self> {
		if !json {
			return action;
		}
		Some(match action {
			Some(SuppressionCli::List { account, .. }) => SuppressionCli::List {
				account,
				json: true,
			},
			Some(SuppressionCli::Add {
				address,
				account,
				reason,
				..
			}) => SuppressionCli::Add {
				address,
				account,
				reason,
				json: true,
			},
			Some(SuppressionCli::Remove {
				address, account, ..
			}) => SuppressionCli::Remove {
				address,
				account,
				json: true,
			},
			Some(SuppressionCli::Show {
				address, account, ..
			}) => SuppressionCli::Show {
				address,
				account,
				json: true,
			},
			Some(SuppressionCli::Export { account, .. }) => SuppressionCli::Export {
				account,
				json: true,
			},
			Some(SuppressionCli::Import {
				file,
				account,
				reason,
				dry_run,
				..
			}) => SuppressionCli::Import {
				file,
				account,
				reason,
				dry_run,
				json: true,
			},
			None => match address_to_remove {
				Some(address) => SuppressionCli::Remove {
					address,
					account,
					json: true,
				},
				None => SuppressionCli::List {
					account,
					json: true,
				},
			},
		})
	}
}

/// Add `address` to the suppression list (the global one, or `account`'s).
pub(super) fn add(
	config: &Config,
	address: &str,
	account: Option<&str>,
	reason: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// Anything that is not a deliverable address would sit in the list
	// forever and match nothing, so refuse it up front.
	if let Err(why) = crate::util::address_reason::parse(address) {
		return super::exit::refused(format_args!("cannot suppress: {why}"));
	}
	if let Some(problem) = reason.and_then(exchange::reason_problem) {
		return super::exit::refused(problem);
	}
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let address = crate::util::address::normalize(address);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0);
	let reason = reason.unwrap_or("added by hand (epistle suppression add)");
	let (written, line) = match account {
		Some(account) => (
			list.try_suppress_for_because(account, &address, reason, now),
			format!("suppressed {address} for {account}"),
		),
		None => (
			list.try_suppress_because(&address, reason, now),
			format!("suppressed {address}"),
		),
	};
	// A marker that was not written is not a suppression: say so.
	if let Err(error) = written {
		super::style::error(format_args!("cannot suppress {address}: {error}"));
		return ExitCode::FAILURE;
	}
	let mut report = super::json_out::Report::new(out, json);
	report.line(line);
	let fields = serde_json::json!({ "address": address, "account": account, "reason": reason });
	report.change("add", true, fields, None)
}

/// Remove one address from the suppression list (the per-account
/// table when `account` is `Some`).
pub(super) fn remove(
	config: &Config,
	address: &str,
	account: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let result = match account {
		Some(account) => list.remove_for(account, address),
		None => list.remove(address),
	};
	match result {
		Ok(()) => {
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("removed {address}"));
			let fields = serde_json::json!({ "address": address, "account": account });
			report.change("remove", true, fields, None)
		}
		Err(error) => {
			super::style::error(format_args!("cannot remove {address}: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// Run every suppression action. Each branch opens the list itself so
/// the dispatchers (resource form and the legacy `--remove` form)
/// share the same exit-code and error wording.
pub(super) fn run(
	config: &Config,
	action: SuppressionCli,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match action {
		SuppressionCli::List { account, json } => list(config, account.as_deref(), json, out),
		SuppressionCli::Add {
			address,
			account,
			reason,
			json,
		} => add(
			config,
			&address,
			account.as_deref(),
			reason.as_deref(),
			json,
			out,
		),
		SuppressionCli::Remove {
			address,
			account,
			json,
		} => remove(config, &address, account.as_deref(), json, out),
		SuppressionCli::Show {
			address,
			account,
			json,
		} => super::resource::exit_resource(exchange::show(
			config,
			&address,
			account.as_deref(),
			json,
			out,
		)),
		SuppressionCli::Export { account, json } => {
			super::resource::exit_resource(exchange::export(config, account.as_deref(), json, out))
		}
		SuppressionCli::Import {
			file,
			account,
			reason,
			dry_run,
			json,
		} => {
			let request = exchange::Import {
				file: &file,
				account: account.as_deref(),
				reason: reason.as_deref(),
				dry_run,
				json,
			};
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map_or(0, |elapsed| elapsed.as_secs());
			super::resource::exit_resource(exchange::import(config, request, now, out))
		}
	}
}

/// Compatibility shim for the legacy `epistle suppression` (no action)
/// and `epistle suppression --remove ADDR` forms. The flat forms stay
/// supported as hidden aliases, but the resource form is the entry
/// point the help text shows.
pub(super) fn run_legacy(
	config: &Config,
	address_to_remove: Option<&str>,
	account: Option<&str>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if let Some(address) = address_to_remove {
		return remove(config, address, account, false, out);
	}
	list(config, account, false, out)
}

/// Print every suppressed address in `account`'s scope (global when
/// `account` is `None`), one per line or, with `json`, as an array.
fn list(
	config: &Config,
	account: Option<&str>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let list = match SuppressionList::open(&config.data_dir) {
		Ok(list) => list,
		Err(error) => {
			super::style::error(format_args!("cannot open suppression list: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let entries = match account {
		Some(account) => list.entries_for(account),
		None => list.entries(),
	};
	let since = |entry: &crate::queue::Suppressed| entry.since.map(crate::clock::rfc3339);
	if json {
		let rows: Vec<_> = entries
			.iter()
			.map(|entry| {
				serde_json::json!({
					"address": entry.address,
					"account": account,
					"since": since(entry),
					"reason": entry.reason,
				})
			})
			.collect();
		return super::json_out::print(out, &serde_json::Value::Array(rows));
	}
	// One address per line; when the date and the reason were recorded they
	// follow, tab separated, so `cut -f1` still yields the bare addresses.
	for entry in &entries {
		let address = super::term::sanitize(&entry.address);
		let line = match (since(entry), &entry.reason) {
			(Some(since), Some(reason)) => {
				format!("{address}\t{since}\t{}", super::term::sanitize(reason))
			}
			_ => address,
		};
		if writeln!(out, "{line}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "suppression_tests_reason.rs"]
mod tests_reason;
