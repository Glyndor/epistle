//! The nested actions of `epistle account`: `address`, `forward`,
//! `catch-all` and `2fa`, each with its own verbs.

use clap::{Args, Subcommand as ClapSubcommand};

/// Sub-action on `epistle account forward`.
#[derive(Debug, Args)]
pub struct ForwardArgs {
	/// The list|add|remove verb on the forward list.
	#[command(subcommand)]
	pub action: ForwardSubcommand,
}

/// What to do with one forward target on one account.
#[derive(Debug, ClapSubcommand)]
pub enum ForwardSubcommand {
	/// Print every forward target the account has.
	List {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// Print a JSON array of `{"address"}` objects.
		#[arg(long)]
		json: bool,
	},
	/// Add an external address to the account's forward list.
	Add {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// The destination address (must be a valid mail address and not
		/// one of the account's own addresses).
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
	/// Drop a forward target from the account's list.
	Remove {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// The destination address to remove (must already be on the
		/// list).
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
}

/// Sub-action on `epistle account 2fa`.
#[derive(Debug, Args)]
pub struct TwoFactorArgs {
	/// show prints enrolment status, disable clears the TOTP secret.
	#[command(subcommand)]
	pub action: TwoFactorSubcommand,
}

/// What to do with the account's TOTP enrolment.
#[derive(Debug, ClapSubcommand)]
pub enum TwoFactorSubcommand {
	/// Print whether the account has a TOTP secret enrolled (never the
	/// secret itself).
	Show {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// Print a JSON object `{"name", "enrolled"}`.
		#[arg(long)]
		json: bool,
	},
	/// Remove the account's TOTP secret.
	///
	/// Drop the TOTP secret so the account can log in with its password alone.
	/// Destructive: a confirmation prompt opens on a terminal.
	Disable {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2.
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

/// Sub-action on `epistle account catch-all`.
#[derive(Debug, Args)]
pub struct CatchAllArgs {
	/// The list|add|remove verb on the catch-all list.
	#[command(subcommand)]
	pub action: CatchAllSubcommand,
}

/// What to do with one catch-all domain on one account.
#[derive(Debug, ClapSubcommand)]
pub enum CatchAllSubcommand {
	/// Print every catch-all domain the account serves.
	List {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// Print a JSON array of `{"domain"}` objects.
		#[arg(long)]
		json: bool,
	},
	/// Add a configured domain to the account's catch-all list.
	Add {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// A configured domain (must already be served by this server).
		#[arg(value_name = "DOMAIN")]
		domain: String,
	},
	/// Drop a domain from the account's catch-all list.
	Remove {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// A domain currently on the catch-all list.
		#[arg(value_name = "DOMAIN")]
		domain: String,
	},
}

/// Sub-action on `epistle account address`.
#[derive(Debug, Args)]
pub struct AddressArgs {
	/// Add or remove the address.
	#[command(subcommand)]
	pub action: AddressSubcommand,
}

/// Add or remove a single address.
#[derive(Debug, ClapSubcommand)]
pub enum AddressSubcommand {
	/// Append the address to the account.
	Add {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// The address to add.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
	/// Drop the address from the account (cannot remove the last one).
	Remove {
		/// The account login name.
		#[arg(value_name = "NAME", value_parser = crate::cli::account_name::parse)]
		name: String,
		/// The address to remove.
		#[arg(value_name = "ADDRESS")]
		address: String,
	},
}
