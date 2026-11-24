//! The one way the address aliases change: `epistle alias` and the
//! `/api/v1/aliases` routes both describe what they want as a [`Change`] and
//! hand it to [`commit`], so the command and the routes run the same rules
//! and give the same refusals.
//!
//! [`commit`] goes through [`crate::editable::commit()`]: the cross-process
//! lock of the state file, a fresh read (or, when the file does not exist yet,
//! what the configuration file declares), the change with the rules in
//! [`rules`], a check that the configuration the server would load with the
//! result is valid, and an atomic write. A change that leaves the file as it
//! was writes nothing.
//!
//! Who asks matters in two places, and both are one parameter of the same
//! rules and not a second code path: the [`Origin`]. The operator at the
//! command line may name members the directory cannot route to, as the
//! command always could. A key of the API may not: its members are addresses
//! of accounts that exist, and the alias and every member are inside the
//! domains the key is confined to.

use crate::config::Config;
use crate::editable::CommitError;
use crate::limits::LimitReached;

use super::file::AliasesFile;

mod caps;
mod collide;
pub mod rules;

/// Who asks for a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
	/// The operator at the command line.
	Operator,
	/// A key of the management API.
	Api {
		/// The domains the key is confined to, `None` for a key that is not.
		confined_to: Option<Vec<String>>,
	},
}

impl Origin {
	/// Whether this is a key of the API.
	pub fn is_api(&self) -> bool {
		matches!(self, Origin::Api { .. })
	}

	/// Whether this is a key of the API that is confined to some domains.
	pub fn is_confined(&self) -> bool {
		matches!(
			self,
			Origin::Api {
				confined_to: Some(_)
			}
		)
	}

	/// Whether `domain` is one the origin may act in.
	pub fn admits_domain(&self, domain: &str) -> bool {
		match self {
			Origin::Api {
				confined_to: Some(domains),
			} => domains
				.iter()
				.any(|allowed| allowed.eq_ignore_ascii_case(domain)),
			_ => true,
		}
	}
}

/// The alias an add makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAlias {
	/// The alias address as the caller wrote it.
	pub address: String,
	/// The member addresses, at least one.
	pub members: Vec<String>,
	/// Addresses allowed to send as the alias. Empty means any member.
	pub senders: Vec<String>,
	/// The mailing-list identifier, when the alias is a list.
	pub list_id: Option<String>,
	/// Whether the membership stays out of directory queries.
	pub hidden: bool,
}

/// One change to the alias state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
	/// Add an alias.
	Add(NewAlias),
	/// Remove an alias.
	Remove {
		/// The alias address.
		address: String,
	},
	/// Add a member to an alias.
	MemberAdd {
		/// The alias address.
		address: String,
		/// The member address.
		member: String,
	},
	/// Remove a member from an alias.
	MemberRemove {
		/// The alias address.
		address: String,
		/// The member address.
		member: String,
	},
	/// Allow an address to send as an alias.
	SenderAdd {
		/// The alias address.
		address: String,
		/// The sender address.
		sender: String,
	},
	/// Stop an address from sending as an alias.
	SenderRemove {
		/// The alias address.
		address: String,
		/// The sender address.
		sender: String,
	},
}

impl Change {
	/// The alias address the change is about, as the caller wrote it.
	pub fn address(&self) -> &str {
		match self {
			Change::Add(new) => &new.address,
			Change::Remove { address }
			| Change::MemberAdd { address, .. }
			| Change::MemberRemove { address, .. }
			| Change::SenderAdd { address, .. }
			| Change::SenderRemove { address, .. } => address,
		}
	}
}

/// Why a [`Change`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasError {
	/// The alias, or what the origin may not tell from one, is not there.
	NotFound(String),
	/// An address, a member or the result is not valid.
	Invalid(String),
	/// The alias, the member or the sender is already there.
	Exists(String),
	/// A cap of the server: aliases, lists or members of a domain.
	Capped(LimitReached),
	/// The state file could not be locked, read or written.
	Io(String),
}

impl std::fmt::Display for AliasError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AliasError::NotFound(message)
			| AliasError::Invalid(message)
			| AliasError::Exists(message)
			| AliasError::Io(message) => formatter.write_str(message),
			AliasError::Capped(reached) => write!(formatter, "{reached}"),
		}
	}
}

impl std::error::Error for AliasError {}

/// The outcome of a [`commit`] or a [`preview`].
pub type Committed = crate::editable::Committed<AliasesFile>;

fn refusal(error: CommitError<AliasError>) -> AliasError {
	match error {
		CommitError::Refused(error) => error,
		CommitError::Invalid(message) => AliasError::Invalid(message),
		CommitError::Io(message) => AliasError::Io(message),
	}
}

/// Apply `change` for `origin` under the lock of the state file of `config`'s
/// data directory and write the result. `config` is the configuration as
/// loaded: its seed is what a missing state file starts from.
///
/// The lock of `domains.toml` is taken first and the one of the alias file
/// second, the order a domain removal also uses, so the hosted domains an
/// alias is checked against cannot change under the write.
pub fn commit(config: &Config, change: &Change, origin: &Origin) -> Result<Committed, AliasError> {
	let domains = crate::domain::state::path(&config.data_dir);
	let _hosted =
		crate::storage::lock::FileLock::acquire(&crate::storage::locked::lock_path(&domains))
			.map_err(|error| AliasError::Io(format!("{}: {error}", domains.display())))?;
	let fresh = config.with_current_domains_file();
	crate::editable::commit(&fresh, |current: &Config, file: &mut AliasesFile| {
		rules::apply(current, file, change, origin)
	})
	.map_err(refusal)
}

/// What [`commit`] would do, without the lock and without writing: for a dry
/// run.
pub fn preview(config: &Config, change: &Change, origin: &Origin) -> Result<Committed, AliasError> {
	let fresh = config.with_current_domains_file();
	crate::editable::preview(&fresh, |current: &Config, file: &mut AliasesFile| {
		rules::apply(current, file, change, origin)
	})
	.map_err(refusal)
}

/// Write the state file from what the configuration file declares when it
/// does not exist yet. Returns whether it was written. `serve` calls this at
/// start, so the server reloads the same file every later write changes.
pub fn seed(config: &Config) -> Result<bool, AliasError> {
	crate::editable::seed::<AliasesFile>(config).map_err(|error| {
		AliasError::Io(format!(
			"{}: {error}",
			super::path(&config.data_dir).display()
		))
	})
}
