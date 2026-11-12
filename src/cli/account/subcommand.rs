//! The `epistle account` umbrella subcommand enum.

use super::*;

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
		/// Show under each account the address aliases that deliver to it.
		///
		/// A disabled alias is marked, not hidden. With `--json` each account
		/// gains an `aliases` array of `{"address", "enabled", "hidden"}`.
		#[arg(long)]
		aliases: bool,
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
		/// The person's name, shown as the sender name (any case and script).
		#[arg(long, value_name = "TEXT")]
		display_name: Option<String>,
	},
	/// Set the display name of a dynamic account; an empty one clears it.
	SetName {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// The person's name, kept as written.
		#[arg(value_name = "DISPLAY_NAME")]
		display_name: String,
	},
	/// Remove a dynamic account and everything it owns.
	///
	/// That is its mailbox, masked addresses, app passwords, suppression
	/// entries and, with `--queue discard`, its queued mail.
	Remove {
		/// Account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
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
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
	},
	/// Disable an account.
	///
	/// Authentication rejects it identically to an unknown login while the
	/// mailbox stays on disk; re-enable with `account enable`.
	Disable {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
	},
	/// Re-enable a previously disabled account.
	Enable {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
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
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
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
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// The protocol allowlist, comma-separated
		/// (`imap,smtp,api,webdav`), or `all` to clear.
		#[arg(value_name = "LIST")]
		list: String,
	},
	/// Change account settings.
	///
	/// `--default-class` sets the class granted to the account's mail when
	/// neither the request nor the credential names one (`none` clears it).
	/// `--send` and `--receive` switch sending and receiving on or off, each
	/// independent of `account disable` and of `account protocols`; a switch
	/// left out keeps its state, and both are on by default.
	#[command(group(
		clap::ArgGroup::new("setting")
			.required(true)
			.multiple(true)
			.args(["default_class", "send", "receive"])
	))]
	Set {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
		name: String,
		/// `transactional`, `marketing`, `personal`, or `none`.
		#[arg(
			long = "default-class",
			value_name = "CLASS",
			conflicts_with_all = ["send", "receive"]
		)]
		default_class: Option<String>,
		/// `on` or `off`: whether the account may send mail.
		#[arg(long, value_name = "STATE")]
		send: Option<String>,
		/// `on` or `off`: whether mail addressed to the account is accepted.
		#[arg(long, value_name = "STATE")]
		receive: Option<String>,
	},
	/// Set whether the server saves a Sent copy of every send.
	SaveSent {
		/// The account login name.
		#[arg(value_name = "NAME")]
		name: String,
		/// `on` or `off`. The default (no account setting) is "on";
		/// `off` is the opt-out.
		#[arg(value_name = "STATE")]
		state: String,
	},
	/// Print the public view of an account, never its secrets.
	///
	/// Print the public view of an account (addresses, disabled, quota,
	/// protocols, log id). Never secrets.
	Show {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account::name::parse)]
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
