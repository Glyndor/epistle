//! The one way the hosted-domain state changes: `epistle domain` and the
//! `/api/v1/domains` routes both describe what they want as a [`Change`] and
//! hand it to [`commit`].
//!
//! [`commit`] goes through [`crate::editable::commit()`]: the cross-process
//! lock of the state file, a fresh read (or, when the file does not exist
//! yet, what the configuration file declares), the change with the rules in
//! [`rules`], a check that the configuration the server would load with the
//! result is valid, and an atomic write. A change that leaves the file as it
//! was writes nothing.

use crate::config::Config;
use crate::editable::CommitError;

use super::file::{DomainsFile, OwnKey, StoredRole};

pub mod add;
pub mod rules;

/// One change to the hosted-domain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
	/// Host a new domain.
	Add {
		/// The domain as the caller wrote it.
		name: String,
		/// Its role.
		role: StoredRole,
		/// The DKIM key made for it, when it signs with a key of its own.
		dkim: Option<OwnKey>,
		/// The SRS secret made for it.
		srs_secret: Option<String>,
	},
	/// Stop hosting a domain.
	Remove {
		/// The domain.
		name: String,
	},
	/// Give a domain a role.
	SetRole {
		/// The domain.
		name: String,
		/// The role.
		role: StoredRole,
	},
	/// Switch a domain on or off.
	SetEnabled {
		/// The domain.
		name: String,
		/// `true` to switch it on.
		enabled: bool,
	},
	/// Make an alias domain resolve as a hosted domain.
	AliasAdd {
		/// The alias domain.
		alias: String,
		/// The hosted domain it resolves as.
		target: String,
	},
	/// Drop a domain alias.
	AliasRemove {
		/// The alias domain.
		alias: String,
	},
	/// Replace the state with what the configuration file declares.
	Import,
}

/// Why a [`Change`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
	/// The domain or alias the change names is not there.
	NotFound(String),
	/// The name is not a valid domain name, or the result would be a
	/// configuration the server refuses.
	Invalid(String),
	/// The domain or alias is already there, or the name is taken.
	Exists(String),
	/// The domain is still used by accounts, aliases or the configuration
	/// file.
	InUse(String),
	/// A rule of the server: the last enabled domain of a server with
	/// listeners cannot be switched off.
	Policy(String),
	/// The state file could not be locked, read or written.
	Io(String),
}

impl std::fmt::Display for EditError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			EditError::NotFound(message)
			| EditError::Invalid(message)
			| EditError::Exists(message)
			| EditError::InUse(message)
			| EditError::Policy(message)
			| EditError::Io(message) => formatter.write_str(message),
		}
	}
}

impl std::error::Error for EditError {}

/// The outcome of a [`commit`] or a [`preview`].
pub type Committed = crate::editable::Committed<DomainsFile>;

fn refusal(error: CommitError<EditError>) -> EditError {
	match error {
		CommitError::Refused(error) => error,
		CommitError::Invalid(message) => EditError::Invalid(message),
		CommitError::Io(message) => EditError::Io(message),
	}
}

/// Apply `change` under the lock of the state file of `config`'s data
/// directory and write the result. `config` is the configuration as loaded:
/// its seed is what a missing state file starts from.
pub fn commit(config: &Config, change: &Change) -> Result<Committed, EditError> {
	crate::editable::commit(config, |current: &Config, file: &mut DomainsFile| {
		rules::apply(current, file, change)
	})
	.map_err(refusal)
}

/// What [`commit`] would do, without the lock and without writing: for a
/// dry run.
pub fn preview(config: &Config, change: &Change) -> Result<Committed, EditError> {
	crate::editable::preview(config, |current: &Config, file: &mut DomainsFile| {
		rules::apply(current, file, change)
	})
	.map_err(refusal)
}

/// Write the state file from what the configuration file declares when it
/// does not exist yet. Returns whether it was written. `serve` calls this at
/// start, so the server reloads the same file every later write changes.
pub fn seed(config: &Config) -> Result<bool, EditError> {
	crate::editable::seed::<DomainsFile>(config).map_err(|error| {
		EditError::Io(format!(
			"{}: {error}",
			super::path(&config.data_dir).display()
		))
	})
}

#[cfg(test)]
mod tests;
