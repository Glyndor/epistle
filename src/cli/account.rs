//! `epistle account …`: in-place mutators on a dynamic account that
//! would otherwise need an `accounts.toml` edit and a server reload.
//!
//! The action list is intentionally narrow: each subcommand maps to a
//! single `AccountStore` mutator, refuses a static account with a
//! message that tells the operator to edit the config file, and
//! returns `ExitCode::SUCCESS` only when the mutator reports success.
//! Anything beyond a thin wrapper here would belong on the store's
//! mutator, not on the CLI handler.
//!
//! The store lives in `<data_dir>/accounts.toml`; the running server
//! watches the file and rebuilds its directory within a few seconds,
//! so no service restart is needed. The watcher reload API is the same
//! one the sibling process drives from `add`, `remove` and
//! `set_password_hash`.

use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand as ClapSubcommand;

use crate::cli::style;
use crate::config::{Config, Protocol};
use crate::directory_store::{AccountStore, StoreError};

#[path = "account_actions.rs"]
mod account_actions;
#[path = "account_args.rs"]
mod account_args;
#[path = "account_forward_catch_all.rs"]
mod account_forward_catch_all;
#[path = "account_two_factor.rs"]
mod account_two_factor;
#[allow(unused_imports)]
pub(super) use account_actions::{
	address_add_with_store, address_remove_with_store, disable_with_store, enable_with_store,
	find_log_id_with_store, handle_error, password_with_store, protocols_changed,
	protocols_with_store, quota_changed, quota_with_store, render, render_protocols,
	show_with_store,
};
pub use account_args::{
	AddressArgs, AddressSubcommand, CatchAllArgs, CatchAllSubcommand, ForwardArgs,
	ForwardSubcommand, TwoFactorArgs, TwoFactorSubcommand,
};
#[allow(unused_imports)]
pub(super) use account_forward_catch_all::{
	catch_all_add_with_store, catch_all_list, catch_all_remove_with_store, forward_add_with_store,
	forward_list, forward_remove_with_store,
};
#[allow(unused_imports)]
pub(super) use account_two_factor::{two_factor_disable, two_factor_show};

/// Every action the `epistle account` umbrella command understands.
/// Each maps to a single handler below; `clap` deserialises the trailing
/// positional arguments into the right variant. The first line of each
/// `about` must stay under 80 characters so the umbrella's `--help`
/// block fits one terminal page; longer context moves to `long_about`.
#[derive(Debug, ClapSubcommand)]
pub enum Subcommand {
	/// List every account (static and dynamic) with its addresses and source.
	List {
		/// Print a JSON array of `{"name", "source", "addresses"}` objects.
		#[arg(long)]
		json: bool,
	},
	/// Create a dynamic account.
	///
	/// Password is asked twice with echo off on a terminal, one line from stdin
	/// otherwise.
	Add {
		/// Account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// An email address for the account (repeatable).
		#[arg(long = "address", value_name = "ADDR", required = true)]
		addresses: Vec<String>,
	},
	/// Remove a dynamic account and everything it owns.
	///
	/// That is its mailbox, masked addresses, app passwords, suppression
	/// entries and, with `--queue discard`, its queued mail.
	Remove {
		/// Account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// What to do with queued outbound mail: `discard` (drop) or `drain`
		/// (leave it for delivery). Required.
		#[arg(long = "queue", value_name = "POLICY", value_parser = crate::cli::accounts::parse_queue_policy)]
		queue: crate::directory_store::removal::QueuePolicy,
		/// Skip the interactive confirmation. A non-interactive run without
		/// `--yes` is refused with exit code 2.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Change an account's password.
	///
	/// Update the password for an account: asked twice with echo off on a
	/// terminal, read from stdin (one line) otherwise. Hashes it with argon2id
	/// and derives a fresh SCRAM salt, exactly the way account-add does on a
	/// fresh account.
	Password {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Disable an account.
	///
	/// Authentication rejects it identically to an unknown login while the
	/// mailbox stays on disk; re-enable with `account enable`.
	Disable {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Re-enable a previously disabled account.
	Enable {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
	},
	/// Add or remove a delivery address for the account.
	Address(AddressArgs),
	/// Set the account's storage quota (500M, 10G, 1T or none).
	///
	/// Set the storage quota for the account (e.g. `500M`, `10G`, `1T`, or
	/// `none` for the server default).
	Quota {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The quota size (accepts `K`, `M`, `G`, `T` suffixes and the
		/// literal `none` for the server default).
		#[arg(value_name = "SIZE")]
		size: String,
	},
	/// Restrict which protocols the account may sign in through.
	///
	/// Restrict which authentication protocols the account may sign in through.
	/// `all` clears the restriction.
	Protocols {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// The protocol allowlist, comma-separated
		/// (`imap,smtp,api,webdav`), or `all` to clear.
		#[arg(value_name = "LIST")]
		list: String,
	},
	/// Print the public view of an account, never its secrets.
	///
	/// Print the public view of an account (addresses, disabled, quota,
	/// protocols, log id). Never secrets.
	Show {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// Print one JSON object instead of `key: value` lines.
		#[arg(long)]
		json: bool,
	},
	/// Map a log pseudonym back to the account it stands for.
	///
	/// Map a log pseudonym (`acct-` plus 12 hex characters) back to the account
	/// it stands for, using this server's pseudonym key.
	FindLogId {
		/// The pseudonym as it appears in the server log.
		#[arg(value_name = "LOG_ID")]
		log_id: String,
	},
	/// Inspect or remove the account's two-factor (TOTP) enrolment.
	#[command(name = "2fa", alias = "two-factor")]
	TwoFactor(TwoFactorArgs),
	/// Manage the addresses an account's mail is also sent to.
	///
	/// Manage per-account forward targets (extra addresses a delivered message
	/// is also sent to).
	Forward(ForwardArgs),
	/// Manage the domains whose unknown users reach this account.
	///
	/// Manage per-account catch-all domains (deliver unknown local users in a
	/// domain to this account).
	CatchAll(CatchAllArgs),
}

/// A byte suffix (K, M, G, T) parsed from the operator's quota string.
/// Stored as the multiplicative factor so the parser can be reused for
/// any case-sensitive unit without an extra lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaUnit {
	/// 2^10 bytes.
	K,
	/// 2^20 bytes.
	M,
	/// 2^30 bytes.
	G,
	/// 2^40 bytes.
	T,
}

impl QuotaUnit {
	fn factor(self) -> u64 {
		match self {
			QuotaUnit::K => 1024,
			QuotaUnit::M => 1024 * 1024,
			QuotaUnit::G => 1024 * 1024 * 1024,
			QuotaUnit::T => 1024 * 1024 * 1024 * 1024,
		}
	}
}

/// Parse a quota argument (`500M`, `10G`, `1T`, `none`) into bytes or
/// `None` for the server-default fallback. Rejects empty strings,
/// negative numbers and unknown suffixes so a typo never lands on disk.
pub(super) fn parse_quota_size(raw: &str) -> Result<Option<u64>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("quota size is empty (expected 500M, 10G, 1T or none)".to_string());
	}
	if trimmed.eq_ignore_ascii_case("none") {
		return Ok(None);
	}
	let split_at = trimmed
		.find(|c: char| !c.is_ascii_digit())
		.ok_or_else(|| format!("quota size {raw:?} needs a K/M/G/T suffix or 'none'"))?;
	let (number, suffix) = trimmed.split_at(split_at);
	if number.is_empty() {
		return Err(format!("quota size {raw:?} starts with a non-digit"));
	}
	let multiplier: u64 = number
		.parse()
		.map_err(|error| format!("quota size {raw:?}: {error}"))?;
	let unit_char = suffix
		.chars()
		.next()
		.ok_or_else(|| format!("quota size {raw:?} is missing a unit"))?;
	let unit = match unit_char {
		'K' | 'k' => QuotaUnit::K,
		'M' | 'm' => QuotaUnit::M,
		'G' | 'g' => QuotaUnit::G,
		'T' | 't' => QuotaUnit::T,
		other => {
			return Err(format!(
				"quota size {raw:?}: unknown unit {other:?} (expected K, M, G or T)"
			));
		}
	};
	if !suffix.chars().skip(1).all(|c| c.is_whitespace()) {
		return Err(format!(
			"quota size {raw:?}: trailing characters after unit"
		));
	}
	multiplier
		.checked_mul(unit.factor())
		.map(Some)
		.ok_or_else(|| format!("quota size {raw:?} overflows u64"))
}

/// Parse a protocol-list argument (`imap,smtp`, `all`). Unknown
/// protocol names are rejected with a list of the accepted ones so a
/// typo never reaches the store. `all` (case-insensitive) returns
/// `Ok(None)` to clear the restriction.
pub(super) fn parse_protocol_list(raw: &str) -> Result<Option<Vec<Protocol>>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("protocol list is empty (expected imap,smtp or 'all')".to_string());
	}
	if trimmed.eq_ignore_ascii_case("all") {
		return Ok(None);
	}
	let mut out = Vec::new();
	for token in trimmed.split(',') {
		let name = token.trim();
		if name.is_empty() {
			return Err("protocol list has an empty entry".to_string());
		}
		let protocol = parse_protocol(name)?;
		if !out.contains(&protocol) {
			out.push(protocol);
		}
	}
	Ok(Some(out))
}

/// Parse a single protocol name. Duplicates the kebab-case spellings
/// the TOML `Protocol` deserialiser already understands so the CLI
/// list and the config file spell them the same way.
fn parse_protocol(name: &str) -> Result<Protocol, String> {
	match name.to_ascii_lowercase().as_str() {
		"smtp" => Ok(Protocol::Smtp),
		"submission" => Ok(Protocol::Submission),
		"submissions" => Ok(Protocol::Submissions),
		"api" => Ok(Protocol::Api),
		"imap" => Ok(Protocol::Imap),
		"imaps" => Ok(Protocol::Imaps),
		"pop3s" => Ok(Protocol::Pop3s),
		"managesieve" => Ok(Protocol::ManageSieve),
		"webdav" => Ok(Protocol::WebDav),
		other => Err(format!(
			"unknown protocol {other:?} (expected smtp, submission, submissions, api, imap, imaps, pop3s, managesieve, webdav or 'all')"
		)),
	}
}

/// Open the store the action will mutate. Centralising the error
/// handling keeps the per-action branches focused on their mutator.
/// `[auth] scram` is applied here because `account password` derives (or,
/// with SCRAM off, drops) the verifier from the store's flag.
fn open_store(config: &Config) -> Result<AccountStore, StoreError> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_scram_enabled(config.auth.scram))
}

/// `handle_error` lives in `account_actions`; the umbrella module only
/// re-exports it so callers can write `account::handle_error`.
/// Common prelude every mutating action shares: [`prepare_show`], then
/// refuse a static account with the config-file hint. Returns the open
/// store, or has already printed the error and returns
/// `ExitCode::FAILURE` so the caller can early-return. Both refusals run
/// before anything is read from stdin, so nobody types a password for a
/// name that cannot take one.
pub(super) fn prepare(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
	let store = prepare_show(config_path, name)?;
	if store.is_static(name) {
		return Err(crate::cli::exit::refused(format_args!(
			"account {name}: edit the config file to change a static account"
		)));
	}
	Ok(store)
}

/// Load the config, open the store and refuse a name that is neither a
/// static nor a dynamic account with `no such account: <name>`. Static
/// accounts pass: `account show` reports their public view and changes
/// nothing.
pub(super) fn prepare_show(config_path: &Path, name: &str) -> Result<AccountStore, ExitCode> {
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return Err(ExitCode::FAILURE);
		}
	};
	let store = match open_store(&config) {
		Ok(store) => store,
		Err(error) => {
			style::error(format_args!("account {name}: {error}"));
			return Err(ExitCode::FAILURE);
		}
	};
	if !store.account_known(name) {
		return Err(crate::cli::exit::refused(format_args!(
			"no such account: {name}"
		)));
	}
	Ok(store)
}

/// Load the server's log pseudonym key so the pseudonyms this command
/// prints are the ones the running server writes to its log.
fn init_log_id(config_path: &Path) -> Result<(), ExitCode> {
	let config = Config::load(config_path).map_err(|error| {
		style::error(error);
		ExitCode::FAILURE
	})?;
	crate::log_id::init(&config.data_dir).map_err(|error| {
		style::error(format_args!("cannot open the log pseudonym key: {error}"));
		ExitCode::FAILURE
	})
}

/// Dispatch every `epistle account …` subcommand. The umbrella exists
/// so the operator can `tab-complete` from one root and so the
/// per-action handler signatures stay short.
pub(super) fn run(
	config_path: &Path,
	subcommand: Subcommand,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// `list`/`add`/`remove` route to the same handlers the flat
	// `accounts`/`account-add`/`account-remove` commands drive, so the two
	// parsers cannot drift. `list` only reads; `add` is the one action that
	// reads from stdin (a new password) and so re-opens its own prompt
	// reader, while `remove` decides the queue policy before it touches
	// anything.
	match subcommand {
		Subcommand::List { json } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if json {
				return super::account_json::list(&config, out);
			}
			super::accounts::list(&config, out)
		}
		Subcommand::Add { name, addresses } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::add(&config, &name, addresses, super::prompt::stdin())
		}
		Subcommand::Remove { name, queue, yes } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::remove(&config, &name, queue, yes, out)
		}
		Subcommand::Password { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			password_with_store(&store, &name, super::prompt::stdin())
		}
		Subcommand::Disable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			disable_with_store(&store, &name)
		}
		Subcommand::Enable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			enable_with_store(&store, &name)
		}
		Subcommand::Address(args) => match args.action {
			AddressSubcommand::Add { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_add_with_store(&store, &name, &address)
			}
			AddressSubcommand::Remove { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_remove_with_store(&store, &name, &address)
			}
		},
		Subcommand::Quota { name, size } => {
			let parsed = match parse_quota_size(&size) {
				Ok(size) => size,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			quota_with_store(&store, &name, parsed)
		}
		Subcommand::Protocols { name, list } => {
			let parsed = match parse_protocol_list(&list) {
				Ok(list) => list,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			protocols_with_store(&store, &name, parsed)
		}
		Subcommand::Show { name, json } => {
			let store = match prepare_show(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			if let Err(code) = init_log_id(config_path) {
				return code;
			}
			if json {
				return super::account_json::show(&store, &name, out);
			}
			show_with_store(&store, &name, out)
		}
		Subcommand::FindLogId { log_id } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if let Err(error) = crate::log_id::init(&config.data_dir) {
				style::error(format_args!("cannot open the log pseudonym key: {error}"));
				return ExitCode::FAILURE;
			}
			match open_store(&config) {
				Ok(store) => find_log_id_with_store(&store, &log_id, out),
				Err(error) => {
					style::error(format_args!("opening account store: {error}"));
					ExitCode::FAILURE
				}
			}
		}
		// `forward` and `catch-all` accept the same umbrella shape, with a
		// dynamic-only mutator behind each: the dispatcher refuses a
		// static account with the config-file hint before any mutator
		// runs, mirroring `account enable`/`disable`.
		Subcommand::Forward(args) => dispatch_forward(args, config_path, out),
		Subcommand::CatchAll(args) => dispatch_catch_all(args, config_path, out),
		Subcommand::TwoFactor(args) => dispatch_two_factor(args, config_path, out),
	}
}

/// Run `epistle account forward …` against the dynamic store. The
/// mutator refuses a static account so a typo cannot land on disk;
/// refusing up front keeps the prepare/store sequence identical to the
/// rest of the umbrella.
fn dispatch_forward(
	args: ForwardArgs,
	config_path: &Path,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, dynamic_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		ForwardSubcommand::List { name, json: true } => {
			super::account_json::forwards(&store, &name, out)
		}
		ForwardSubcommand::List { name, json: false } => forward_list(&store, &name, out),
		ForwardSubcommand::Add { name, address } => {
			// Delivery rewrites a forwarded envelope sender with SRS only
			// when `srs_secret` is set; without it the next hop checks SPF
			// against the original sender's domain and a `-all` domain
			// rejects the copy. The config loader refuses a static forward
			// for the same reason.
			if Config::load(config_path).is_ok_and(|config| config.srs_secret.is_none()) {
				return crate::cli::exit::refused(format_args!(
					"account {name} forward: set `srs_secret` in the config first; \
					 without SRS a forwarded copy fails SPF at the next hop"
				));
			}
			forward_add_with_store(&store, &name, &address)
		}
		ForwardSubcommand::Remove { name, address } => {
			forward_remove_with_store(&store, &name, &address)
		}
	}
}

/// Run `epistle account catch-all …` against the dynamic store.
fn dispatch_catch_all(
	args: CatchAllArgs,
	config_path: &Path,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, catch_all_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		CatchAllSubcommand::List { name, json: true } => {
			super::account_json::catch_alls(&store, &name, out)
		}
		CatchAllSubcommand::List { name, json: false } => catch_all_list(&store, &name, out),
		CatchAllSubcommand::Add { name, domain } => {
			catch_all_add_with_store(&store, &name, &domain)
		}
		CatchAllSubcommand::Remove { name, domain } => {
			catch_all_remove_with_store(&store, &name, &domain)
		}
	}
}

/// The account name from any forward sub-action. The dispatcher above
/// uses it as the canonical "is this a static account" check before
/// running any mutator.
fn dynamic_name(action: &ForwardSubcommand) -> &str {
	match action {
		ForwardSubcommand::List { name, .. }
		| ForwardSubcommand::Add { name, .. }
		| ForwardSubcommand::Remove { name, .. } => name,
	}
}

/// The account name from any catch-all sub-action.
fn catch_all_name(action: &CatchAllSubcommand) -> &str {
	match action {
		CatchAllSubcommand::List { name, .. }
		| CatchAllSubcommand::Add { name, .. }
		| CatchAllSubcommand::Remove { name, .. } => name,
	}
}

/// Run `epistle account 2fa …` against the dynamic store. The mutator
/// refuses a static account with the config-edit hint before any TOTP
/// action runs, mirroring the rest of the umbrella.
fn dispatch_two_factor(
	args: TwoFactorArgs,
	config_path: &Path,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, two_factor_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		TwoFactorSubcommand::Show { name, json: true } => {
			super::account_json::two_factor(&store, &name, out)
		}
		TwoFactorSubcommand::Show { name, json: false } => two_factor_show(&store, &name, out),
		TwoFactorSubcommand::Disable { name, yes } => two_factor_disable(&store, &name, yes),
	}
}

/// The account name from any 2fa sub-action. The dispatcher above uses
/// it as the canonical "is this a static account" check before any
/// mutator or read runs.
fn two_factor_name(action: &TwoFactorSubcommand) -> &str {
	match action {
		TwoFactorSubcommand::Show { name, .. } | TwoFactorSubcommand::Disable { name, .. } => name,
	}
}
