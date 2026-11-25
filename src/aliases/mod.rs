//! The editable state of the address aliases: the `[[alias]]` entries that
//! fan one address out to several local accounts.
//!
//! The state lives in `<data_dir>/address-aliases.toml`, next to
//! `domains.toml`, so it can change while `/etc/epistle` stays read-only for
//! the server. `epistle alias` and the `/api/v1/aliases` routes write it
//! through [`edit`], under the cross-process lock and the atomic rename of
//! [`crate::editable`], and the running server reloads it the way it reloads
//! the hosted domains. The per-address enabled flag of `epistle alias
//! enable|disable` is a different file, `aliases.json`, and is not part of
//! this state.
//!
//! The configuration file stays the seed. While the file does not exist, the
//! `[[alias]]` entries of the configuration file are the state, unchanged.
//! The first write, or the first start of `serve`, copies them into the file;
//! from then on the file is the one that counts, and a later edit of
//! `[[alias]]` in the configuration file is reported at load and not applied.
//!
//! Loading the configuration applies the file on top of what the
//! configuration file says ([`overlay`]), so every reader of
//! [`crate::config::Config::alias`] sees the same aliases.

pub mod edit;
pub mod file;
pub mod overlay;
pub mod view;

pub use edit::{AliasError, Change, Committed, Origin};
pub use file::AliasesFile;

use std::path::{Path, PathBuf};

use crate::config::Config;

/// The name of the state file inside the data directory.
pub const FILE_NAME: &str = "address-aliases.toml";

/// Where the state file of the data directory `data_dir` lives.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE_NAME)
}

impl crate::editable::StateFile for AliasesFile {
	const FILE_NAME: &'static str = FILE_NAME;

	fn parse(text: &str) -> std::io::Result<Self> {
		AliasesFile::parse(text)
	}

	fn render(&self) -> std::io::Result<String> {
		AliasesFile::render(self)
	}

	fn seed(config: &Config) -> Self {
		config.aliases_seed_file()
	}

	fn apply(config: &Config, state: &Self) -> Config {
		config.with_aliases_file(state)
	}
}

/// The aliases in effect now according to the files on disk, for a check
/// that has to decide against what is written and not against the snapshot a
/// running server holds: the state file when it exists, the configuration
/// file's entries otherwise. A file that cannot be read gives the snapshot.
pub fn current(config: &Config) -> Vec<crate::config::Alias> {
	match AliasesFile::read(&path(&config.data_dir)) {
		Ok(Some(file)) => file.aliases,
		Ok(None) => config
			.alias_seed
			.clone()
			.unwrap_or_else(|| config.alias.clone()),
		Err(_) => config.alias.clone(),
	}
}

#[cfg(test)]
mod tests;
