//! `epistle alias`: inspect and edit multi-target aliases from
//! `[[alias]]` (static config) plus the per-address enabled flag held in
//! `{data_dir}/aliases.json` (a hot-reloaded dynamic store, not the
//! config engine).

use std::io::Write;

use super::term::table::Table;
use std::path::Path;
use std::process::ExitCode;

use clap::{ArgAction, Args, Subcommand};

use crate::aliases::view::{self, AliasRow};
use crate::config::Config;

use super::style;

pub(in crate::cli) use helpers::disabled_set;

mod dispatch;
mod helpers;
mod state;
mod writers;
use dispatch::{Outcome, execute};

/// Multi-target alias administration.
#[derive(Debug, Subcommand)]
pub enum AliasCli {
	/// List every configured alias plus its enabled state.
	List {
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Show one alias: members, senders, list-id, hidden, enabled.
	Show {
		/// The alias address (e.g. `team@example.org`).
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Add an alias with at least one member.
	///
	/// Optional senders and `--list-id` identify the alias as a mailing list.
	/// `--visible` overrides the default hidden membership behaviour.
	Add(AddArgs),
	/// Remove an alias entirely.
	Remove {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Edit one alias in place: members and senders.
	Member(MemberArgs),
	/// Edit the allowed senders for one alias.
	Sender(SenderArgs),
	/// Enable an alias that was previously disabled.
	Enable {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
	/// Disable an alias.
	///
	/// The alias address falls through to the next step of delivery resolution
	/// and rejects like one that never existed.
	Disable {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
}

/// Arguments for `epistle alias add`.
#[derive(Debug, Args)]
pub struct AddArgs {
	/// The alias address (e.g. `team@example.org`).
	#[arg(value_name = "ADDRESS")]
	pub address: String,
	/// Member addresses the alias delivers to. At least one is required.
	#[arg(required = true)]
	pub members: Vec<String>,
	/// Addresses allowed to send as this alias. Repeatable. Empty means any
	/// member may; a non-member is always refused.
	#[arg(long = "sender", value_name = "SENDER")]
	pub senders: Vec<String>,
	/// Mailing-list identifier (RFC 2919) attached to delivered copies.
	#[arg(long = "list-id", value_name = "ID")]
	pub list_id: Option<String>,
	/// Publish the membership through directory queries (overrides the
	/// default hidden behaviour).
	#[arg(long, action = ArgAction::SetTrue)]
	pub visible: bool,
}

/// Sub-action on `epistle alias member`.
#[derive(Debug, Args)]
pub struct MemberArgs {
	#[command(subcommand)]
	pub action: MemberSubcommand,
}

/// Add or remove a single member.
#[derive(Debug, Subcommand)]
pub enum MemberSubcommand {
	/// Add a member to the alias.
	Add {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The member address to add.
		#[arg(value_name = "MEMBER")]
		member: String,
	},
	/// Remove a member from the alias.
	Remove {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The member address to remove.
		#[arg(value_name = "MEMBER")]
		member: String,
	},
}

/// Sub-action on `epistle alias sender`.
#[derive(Debug, Args)]
pub struct SenderArgs {
	#[command(subcommand)]
	pub action: SenderSubcommand,
}

/// Add or remove a single sender.
#[derive(Debug, Subcommand)]
pub enum SenderSubcommand {
	/// Allow an address to send as the alias.
	Add {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The sender address to allow.
		#[arg(value_name = "SENDER")]
		sender: String,
	},
	/// Stop an address from sending as the alias.
	Remove {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The sender address to disallow.
		#[arg(value_name = "SENDER")]
		sender: String,
	},
}

/// Run the chosen alias action.
pub(super) fn run(path: &Path, action: AliasCli, dry_run: bool, json: bool) -> ExitCode {
	match execute(path, action, dry_run, json) {
		Outcome::Code(code) => code,
		Outcome::Error(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
		Outcome::Refusal(error) => {
			style::error(error);
			ExitCode::from(super::exit::REFUSED)
		}
	}
}

pub(super) fn list(config: &Config, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	let rows = view::rows(config);
	if json {
		serde_json::to_writer(&mut *out, &rows).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	let state = |row: &AliasRow| if row.enabled { "enabled" } else { "disabled" };
	let visible = |row: &AliasRow| if row.hidden { "hidden" } else { "visible" };
	if let Some(decor) = super::term::stdout(json) {
		let mut table = Table::new(&["ADDRESS", "STATE", "VISIBLE", "MEMBERS"]).state_col(1);
		for row in &rows {
			table.push(vec![
				row.address.clone(),
				state(row).into(),
				visible(row).into(),
				row.members.join(","),
			]);
		}
		return table.write(decor, out);
	}
	writeln!(
		out,
		"{:<40} {:<8} {:<8} {:<20}",
		"ADDRESS", "STATE", "VISIBLE", "MEMBERS"
	)?;
	for row in &rows {
		writeln!(
			out,
			"{:<40} {:<8} {:<8} {:<20}",
			row.address,
			state(row),
			visible(row),
			row.members.join(",")
		)?;
	}
	Ok(())
}

fn show(config: &Config, address: &str, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	let row = view::row(config, address)
		.ok_or_else(|| std::io::Error::other("alias not found".to_string()))?;
	if json {
		serde_json::to_writer(&mut *out, &row).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	writeln!(out, "address\t{}", row.address)?;
	writeln!(out, "members\t{}", row.members.join(","))?;
	if row.senders.is_empty() {
		writeln!(out, "senders\t(any member)")?;
	} else {
		writeln!(out, "senders\t{}", row.senders.join(","))?;
	}
	writeln!(out, "hidden\t{}", if row.hidden { "true" } else { "false" })?;
	match &row.list_id {
		Some(id) => writeln!(out, "list_id\t{id}")?,
		None => writeln!(out, "list_id\tunset")?,
	}
	writeln!(
		out,
		"enabled\t{}",
		if row.enabled { "true" } else { "false" }
	)?;
	Ok(())
}

#[cfg(test)]
mod tests;
