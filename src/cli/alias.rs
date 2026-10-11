//! `epistle alias`: inspect and edit multi-target aliases from
//! `[[alias]]` (static config) plus the per-address enabled flag held in
//! `{data_dir}/aliases.json` (a hot-reloaded dynamic store, not the
//! config engine).

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::{ArgAction, Args, Subcommand};

use crate::config::{Alias, Config};
use crate::directory_store::AccountStore;

use super::config_edit::{ConfigDocument, Outcome};
use super::style;

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
	/// Add an alias with at least one member. Optional senders and
	/// `--list-id` identify the alias as a mailing list. `--visible`
	/// overrides the default hidden membership behaviour.
	Add(AddArgs),
	/// Remove an alias entirely.
	Remove {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
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
	/// Disable an alias. The alias address falls through to the next step
	/// of delivery resolution and rejects like one that never existed.
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
	Add {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The member address to add.
		#[arg(value_name = "MEMBER")]
		member: String,
	},
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
	Add {
		/// The alias address.
		#[arg(value_name = "ADDRESS")]
		address: String,
		/// The sender address to allow.
		#[arg(value_name = "SENDER")]
		sender: String,
	},
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
		Ok(code) => code,
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

fn execute(path: &Path, action: AliasCli, dry_run: bool) -> Result<ExitCode, String> {
	let mut out = std::io::stdout().lock();
	let mut err = style::stderr();
	let config = Config::load(path).map_err(|e| e.to_string())?;
	match action {
		AliasCli::List { json } => {
			list(&config, json, &mut out).map_err(|e| e.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		AliasCli::Show { address, json } => {
			show(&config, &address, json, &mut out).map_err(|e| e.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		AliasCli::Add(args) => {
			let mut document = open(path)?;
			add_alias(&config, &mut document, &args)?;
			commit_and_restart(
				document,
				&args.address,
				"added",
				dry_run,
				&mut out,
				&mut err,
			)
		}
		AliasCli::Remove { address } => {
			let owned_address = address.clone();
			let mut document = open(path)?;
			remove_alias(&config, &mut document, &address)?;
			commit_and_restart(
				document,
				&owned_address,
				"removed",
				dry_run,
				&mut out,
				&mut err,
			)
		}
		AliasCli::Member(args) => {
			let mut document = open(path)?;
			let verb = match &args.action {
				MemberSubcommand::Add { .. } => "member added",
				MemberSubcommand::Remove { .. } => "member removed",
			};
			let address = match &args.action {
				MemberSubcommand::Add { address, .. }
				| MemberSubcommand::Remove { address, .. } => address.clone(),
			};
			member_edit(&config, &mut document, args)?;
			commit_and_restart(document, &address, verb, dry_run, &mut out, &mut err)
		}
		AliasCli::Sender(args) => {
			let mut document = open(path)?;
			let verb = match &args.action {
				SenderSubcommand::Add { .. } => "sender added",
				SenderSubcommand::Remove { .. } => "sender removed",
			};
			let address = match &args.action {
				SenderSubcommand::Add { address, .. }
				| SenderSubcommand::Remove { address, .. } => address.clone(),
			};
			sender_edit(&config, &mut document, args)?;
			commit_and_restart(document, &address, verb, dry_run, &mut out, &mut err)
		}
		AliasCli::Enable { address } => set_enabled(&config, &address, true, &mut out, &mut err),
		AliasCli::Disable { address } => set_enabled(&config, &address, false, &mut out, &mut err),
	}
}

fn open(path: &Path) -> Result<ConfigDocument, String> {
	ConfigDocument::open(path)
}

/// Open the directory store so we can ask it whether an address is already
/// used by an account, another alias or a masked address.
fn open_store(config: &Config) -> Result<AccountStore, String> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|e| e.to_string())
}

/// Validate that an alias address lives in a configured domain and is not
/// already used by another entity the directory resolves. Mirrors the
/// `address_taken` rule on `AccountStore::add` so the operator gets the same
/// refusal the dynamic path would.
fn validate_alias_address(config: &Config, raw: &str, store: &AccountStore) -> Result<(), String> {
	let parsed = crate::smtp::address::Address::parse(raw)
		.map_err(|_| format!("alias address {raw} is not a valid email address"))?;
	if !config
		.domains
		.iter()
		.any(|domain| domain.eq_ignore_ascii_case(parsed.domain()))
	{
		return Err(format!("alias address {raw} is not in a configured domain"));
	}
	// `address_taken` is `pub(super)` inside `mutators.rs`, so the CLI
	// re-implements the rule on the visible surface. The check covers the
	// three places that own a delivery address: static accounts, dynamic
	// accounts and existing aliases; masked addresses live behind a method
	// on `MaskedAddressStore` that the public `AccountStore` does not
	// expose.
	let used_by_account = config
		.accounts
		.iter()
		.flat_map(|account| account.addresses.iter())
		.any(|existing| existing.eq_ignore_ascii_case(raw));
	if used_by_account {
		return Err(format!("alias address {raw} is already used by an account"));
	}
	// dynamic-account rows from the on-disk store
	for dynamic in store.dynamic_accounts() {
		if dynamic
			.addresses
			.iter()
			.any(|existing| existing.eq_ignore_ascii_case(raw))
		{
			return Err(format!("alias address {raw} is already used by an account"));
		}
	}
	// masked addresses (a JSON-backed store on disk)
	let masked_path = config.data_dir.join("masked.json");
	if let Ok(text) = std::fs::read_to_string(&masked_path) {
		if let Ok(file) = serde_json::from_str::<serde_json::Value>(&text) {
			if let Some(addresses) = file.get("addresses").and_then(|v| v.as_object()) {
				for key in addresses.keys() {
					if key.eq_ignore_ascii_case(raw) {
						return Err(format!(
							"alias address {raw} is already used by a masked address"
						));
					}
				}
			}
		}
	}
	Ok(())
}

/// Parse every member/sender address: same rules as `validate_alias_address`
/// but does not check against the store (the alias itself is allowed to
/// deliver to addresses the directory cannot route to, including external
/// addresses).
fn validate_member_or_sender(label: &str, raw: &str) -> Result<(), String> {
	let parsed = crate::smtp::address::Address::parse(raw)
		.map_err(|_| format!("{label} address {raw} is not a valid email address"))?;
	if parsed.local_part().is_empty() || parsed.domain().is_empty() {
		return Err(format!("{label} address {raw} is empty"));
	}
	Ok(())
}

fn list(config: &Config, json: bool, out: &mut impl Write) -> std::io::Result<()> {
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
	writeln!(
		out,
		"{:<40} {:<8} {:<8} {}",
		"ADDRESS", "STATE", "VISIBLE", "MEMBERS"
	)?;
	for alias in &config.alias {
		let enabled = !disabled.contains(&alias.address.to_ascii_lowercase());
		let state = if enabled { "enabled" } else { "disabled" };
		let visible = if alias.hidden { "hidden" } else { "visible" };
		writeln!(
			out,
			"{:<40} {:<8} {:<8} {}",
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

fn find_alias<'a>(config: &'a Config, address: &str) -> Option<&'a Alias> {
	config
		.alias
		.iter()
		.find(|alias| alias.address.eq_ignore_ascii_case(address))
}

/// Read the disabled-overlay file directly when possible, falling back to an
/// empty set on any I/O or parse error so `list`/`show` never block on a
/// malformed JSON file.
fn disabled_set(config: &Config) -> Option<std::collections::HashSet<String>> {
	let path = config.data_dir.join("aliases.json");
	let text = std::fs::read_to_string(&path).ok()?;
	let file: serde_json::Value = serde_json::from_str(&text).ok()?;
	let addresses = file.get("addresses").and_then(|v| v.as_array())?;
	Some(
		addresses
			.iter()
			.filter_map(|value| value.as_str())
			.map(|address| address.to_ascii_lowercase())
			.collect(),
	)
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
	if find_alias(config, &args.address).is_some() {
		return Err(format!("alias {} already exists", args.address));
	}
	let hidden = !args.visible;
	let mut members_array = toml_edit::Array::new();
	for member in &args.members {
		members_array.push(toml_edit::Value::from(member.clone()));
	}
	let mut fields: Vec<(&str, toml_edit::Value)> = Vec::new();
	fields.push(("address", toml_edit::Value::from(args.address.clone())));
	fields.push(("members", toml_edit::Value::Array(members_array)));
	if !args.senders.is_empty() {
		let mut senders_array = toml_edit::Array::new();
		for sender in &args.senders {
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
	document.upsert_element("alias", "address", &args.address, &fields)?;
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
	document.remove_elements("alias", "address", address)?;
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
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			let mut members = alias.members.clone();
			if members
				.iter()
				.any(|existing| existing.eq_ignore_ascii_case(&member))
			{
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
				.filter(|existing| !existing.eq_ignore_ascii_case(&member))
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
			let alias =
				find_alias(config, &address).ok_or_else(|| format!("alias {address} not found"))?;
			let mut senders = alias.senders.clone();
			if senders
				.iter()
				.any(|existing| existing.eq_ignore_ascii_case(&sender))
			{
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
				.filter(|existing| !existing.eq_ignore_ascii_case(&sender))
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

/// Rewrite the members list on an alias table, preserving the rest.
fn upsert_alias_members(
	document: &mut ConfigDocument,
	address: &str,
	members: &[String],
) -> Result<(), String> {
	let mut values = toml_edit::Array::new();
	for member in members {
		values.push(toml_edit::Value::from(member.clone()));
	}
	document.upsert_element(
		"alias",
		"address",
		address,
		&[("members", toml_edit::Value::Array(values))],
	)
}

/// Rewrite the senders list on an alias table.
fn upsert_alias_senders(
	document: &mut ConfigDocument,
	address: &str,
	senders: &[String],
) -> Result<(), String> {
	let mut values = toml_edit::Array::new();
	for sender in senders {
		values.push(toml_edit::Value::from(sender.clone()));
	}
	document.upsert_element(
		"alias",
		"address",
		address,
		&[("senders", toml_edit::Value::Array(values))],
	)
}

fn commit_and_restart(
	document: ConfigDocument,
	address: &str,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	if outcome == Outcome::Unchanged {
		writeln!(status, "alias {address} already {verb}; nothing changed.")
			.map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "alias {address} {verb}.").map_err(|e| e.to_string())?;
	super::config_edit::after_change_with(&config, outcome, true, status, super::stack::run)
}

/// Toggle the disabled flag on a multi-target alias via the dynamic store.
/// This does not flow through the config-edit engine: `aliases.json` lives
/// under `data_dir` and the running server reloads it on the 2 s file
/// watcher, so no restart is required.
fn set_enabled(
	config: &Config,
	address: &str,
	enabled: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	let store = open_store(config)?;
	let alias = find_alias(config, address).ok_or_else(|| format!("alias {address} not found"))?;
	match store.set_alias_enabled(&alias.address, enabled) {
		Ok(previous) => {
			// `previous` is the disabled-state before the call: true means the
			// alias was already disabled. Calling disable twice in a row leaves
			// `previous` = true on the second call and is a no-op (no persist).
			let verb = if enabled { "enabled" } else { "disabled" };
			let transition = if previous == !enabled {
				format!("already {verb}")
			} else {
				verb.to_string()
			};
			writeln!(status, "alias {address} {transition}.").map_err(|e| e.to_string())?;
			// Confirm the new state on stdout for scripts that parse it.
			writeln!(
				out,
				"{}\t{}",
				alias.address,
				if enabled { "enabled" } else { "disabled" }
			)
			.map_err(|e| e.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		Err(error) => Err(format!("cannot update alias {address}: {error}")),
	}
}

#[cfg(test)]
#[path = "alias_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "alias_tests_enable.rs"]
mod tests_enable;
