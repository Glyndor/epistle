//! `epistle alias`: inspect and edit multi-target aliases from
//! `[[alias]]` (static config) plus the per-address enabled flag held in
//! `{data_dir}/aliases.json` (a hot-reloaded dynamic store, not the
//! config engine).

use std::io::Write;

use super::term::table::Table;
use std::path::Path;
use std::process::ExitCode;

use clap::{ArgAction, Args, Subcommand};

use crate::config::Config;

use super::config_edit::ConfigDocument;
use super::style;

use crate::util::address::normalize;
use alias_helpers::{disabled_set, document_address, find_alias, normalized};
use alias_helpers::{validate_alias_address, validate_member_or_sender};
use alias_writers::{upsert_alias_members, upsert_alias_senders};

#[path = "alias_helpers.rs"]
mod alias_helpers;
#[path = "alias_writers.rs"]
mod alias_writers;
#[path = "alias_dispatch.rs"]
mod dispatch;
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
pub(super) fn run(path: &Path, action: AliasCli, dry_run: bool) -> ExitCode {
	match execute(path, action, dry_run) {
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

fn open(path: &Path) -> Result<ConfigDocument, String> {
	ConfigDocument::open(path)
}

/// Open the directory store so we can ask it whether an address is already
/// used by an account, another alias or a masked address.
fn open_store(config: &Config) -> Result<crate::directory_store::AccountStore, String> {
	crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|e| e.to_string())
}

pub(super) fn list(config: &Config, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	let disabled: std::collections::HashSet<String> = disabled_set(config)
		.map(|set| set.into_iter().collect())
		.unwrap_or_default();
	if json {
		let rows: Vec<_> = config
			.alias
			.iter()
			.map(|alias| {
				let address_lower = alias.address.to_ascii_lowercase();
				let enabled = !disabled.contains(&address_lower);
				serde_json::json!({
					"address": alias.address,
					"members": alias.members,
					"senders": alias.senders,
					"hidden": alias.hidden,
					"list_id": alias.list_id,
					"enabled": enabled,
				})
			})
			.collect();
		serde_json::to_writer(&mut *out, &rows).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	if let Some(decor) = super::term::stdout(json) {
		let mut table = Table::new(&["ADDRESS", "STATE", "VISIBLE", "MEMBERS"]).state_col(1);
		for alias in &config.alias {
			let enabled = !disabled.contains(&alias.address.to_ascii_lowercase());
			let state = if enabled { "enabled" } else { "disabled" };
			let visible = if alias.hidden { "hidden" } else { "visible" };
			table.push(vec![
				alias.address.clone(),
				state.into(),
				visible.into(),
				alias.members.join(","),
			]);
		}
		return table.write(decor, out);
	}
	writeln!(
		out,
		"{:<40} {:<8} {:<8} {:<20}",
		"ADDRESS", "STATE", "VISIBLE", "MEMBERS"
	)?;
	for alias in &config.alias {
		let enabled = !disabled.contains(&alias.address.to_ascii_lowercase());
		let state = if enabled { "enabled" } else { "disabled" };
		let visible = if alias.hidden { "hidden" } else { "visible" };
		writeln!(
			out,
			"{:<40} {:<8} {:<8} {:<20}",
			alias.address,
			state,
			visible,
			alias.members.join(",")
		)?;
	}
	Ok(())
}

fn show(config: &Config, address: &str, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	let alias = find_alias(config, address)
		.ok_or_else(|| std::io::Error::other("alias not found".to_string()))?;
	let enabled = disabled_set(config)
		.map(|set| !set.contains(&alias.address.to_ascii_lowercase()))
		.unwrap_or(true);
	if json {
		let row = serde_json::json!({
			"address": alias.address,
			"members": alias.members,
			"senders": alias.senders,
			"hidden": alias.hidden,
			"list_id": alias.list_id,
			"enabled": enabled,
		});
		serde_json::to_writer(&mut *out, &row).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	writeln!(out, "address\t{}", alias.address)?;
	writeln!(out, "members\t{}", alias.members.join(","))?;
	if alias.senders.is_empty() {
		writeln!(out, "senders\t(any member)")?;
	} else {
		writeln!(out, "senders\t{}", alias.senders.join(","))?;
	}
	writeln!(
		out,
		"hidden\t{}",
		if alias.hidden { "true" } else { "false" }
	)?;
	match &alias.list_id {
		Some(id) => writeln!(out, "list_id\t{id}")?,
		None => writeln!(out, "list_id\tunset")?,
	}
	writeln!(out, "enabled\t{}", if enabled { "true" } else { "false" })?;
	Ok(())
}

fn add_alias(config: &Config, document: &mut ConfigDocument, args: &AddArgs) -> Result<(), String> {
	if find_alias(config, &args.address).is_some() {
		return Err(format!("alias {} already exists", args.address));
	}
	let store = open_store(config)?;
	validate_alias_address(config, &args.address, &store)?;
	if args.members.is_empty() {
		return Err(format!("alias {} has no members", args.address));
	}
	for member in &args.members {
		validate_member_or_sender("member", member)?;
	}
	for sender in &args.senders {
		validate_member_or_sender("sender", sender)?;
	}
	let hidden = !args.visible;
	let (address, members, senders) = (
		normalize(&args.address),
		normalized(&args.members),
		normalized(&args.senders),
	);
	let mut members_array = toml_edit::Array::new();
	for member in &members {
		members_array.push(toml_edit::Value::from(member.clone()));
	}
	let mut fields: Vec<(&str, toml_edit::Value)> = Vec::new();
	fields.push(("address", toml_edit::Value::from(address.clone())));
	fields.push(("members", toml_edit::Value::Array(members_array)));
	if !senders.is_empty() {
		let mut senders_array = toml_edit::Array::new();
		for sender in &senders {
			senders_array.push(toml_edit::Value::from(sender.clone()));
		}
		fields.push(("senders", toml_edit::Value::Array(senders_array)));
	}
	if !hidden {
		fields.push(("hidden", toml_edit::Value::from(false)));
	}
	if let Some(list_id) = &args.list_id {
		fields.push(("list_id", toml_edit::Value::from(list_id.clone())));
	}
	document.upsert_element("alias", "address", &address, &fields)?;
	Ok(())
}

fn remove_alias(
	config: &Config,
	document: &mut ConfigDocument,
	address: &str,
) -> Result<(), String> {
	if find_alias(config, address).is_none() {
		return Err(format!("alias {address} not found"));
	}
	let key = document_address(document, address);
	document.remove_elements("alias", "address", &key)?;
	Ok(())
}

fn member_edit(
	config: &Config,
	document: &mut ConfigDocument,
	args: MemberArgs,
) -> Result<(), String> {
	match args.action {
		MemberSubcommand::Add { address, member } => {
			validate_member_or_sender("member", &member)?;
			let member = normalize(&member);
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			let mut members = alias.members.clone();
			if members.iter().any(|existing| normalize(existing) == member) {
				return Err(format!("alias {address} already has member {member}"));
			}
			members.push(member.clone());
			upsert_alias_members(document, &address, &members)?;
			Ok(())
		}
		MemberSubcommand::Remove { address, member } => {
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			if alias.members.len() == 1 {
				return Err(format!(
					"alias {address} would have no members; use `alias remove` instead"
				));
			}
			let mut members: Vec<String> = alias
				.members
				.iter()
				.filter(|existing| normalize(existing) != normalize(&member))
				.cloned()
				.collect();
			if members.len() == alias.members.len() {
				return Err(format!("alias {address} has no member {member}"));
			}
			members.sort();
			upsert_alias_members(document, &address, &members)?;
			Ok(())
		}
	}
}

fn sender_edit(
	config: &Config,
	document: &mut ConfigDocument,
	args: SenderArgs,
) -> Result<(), String> {
	match args.action {
		SenderSubcommand::Add { address, sender } => {
			validate_member_or_sender("sender", &sender)?;
			let sender = normalize(&sender);
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			let mut senders = alias.senders.clone();
			if senders.iter().any(|existing| normalize(existing) == sender) {
				return Err(format!("alias {address} already allows sender {sender}"));
			}
			senders.push(sender.clone());
			upsert_alias_senders(document, &address, &senders)?;
			Ok(())
		}
		SenderSubcommand::Remove { address, sender } => {
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			let senders: Vec<String> = alias
				.senders
				.iter()
				.filter(|existing| normalize(existing) != normalize(&sender))
				.cloned()
				.collect();
			if senders.len() == alias.senders.len() {
				return Err(format!("alias {address} has no sender {sender}"));
			}
			upsert_alias_senders(document, &address, &senders)?;
			Ok(())
		}
	}
}

#[cfg(test)]
#[path = "alias_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "alias_tests_enable.rs"]
mod tests_enable;
#[cfg(test)]
#[path = "alias_tests_unknown.rs"]
mod tests_unknown;
