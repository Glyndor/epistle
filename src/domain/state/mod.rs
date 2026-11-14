//! The editable state of the hosted domains: which domains the server hosts,
//! the role of each, whether it is switched on, and the domain aliases.
//!
//! The state lives in `<data_dir>/domains.toml`, next to `accounts.toml` and
//! `api_keys.toml`, so it can change while `/etc/epistle` stays read-only for
//! the server. `epistle domain` and the `/api/v1/domains` routes write it
//! through [`edit`], under the same cross-process lock and atomic rename the
//! other data-directory stores use, and the running server reloads it the
//! way it reloads them. The file is one [`crate::editable::StateFile`]: the
//! seed, the lock, the atomic write, the check against the configuration the
//! server would load and the live reload are shared with the other parts of
//! the configuration that move to the data directory.
//!
//! The configuration file stays the seed. While `domains.toml` does not
//! exist, `domains`, `domain_aliases` and the role and switch lists of the
//! configuration file are the state, unchanged. The first write, or the first
//! start of `serve`, copies them into `domains.toml` ([`seed`]); from then on
//! the file in the data directory is the one that counts, and
//! `epistle domain import` copies the configuration file's lists again.
//!
//! Loading the configuration applies the file on top of what the
//! configuration file says ([`overlay`]), so every reader of
//! [`crate::config::Config::domains`] sees the same hosted set.

pub mod blockers;
pub mod edit;
pub mod file;
pub mod overlay;
pub mod seed;

pub use edit::{Change, Committed, EditError};
pub use file::{DomainsFile, HostedDomain, OwnKey, StoredRole};
pub use seed::DomainSeed;

use std::path::{Path, PathBuf};

/// The name of the state file inside the data directory.
pub const FILE_NAME: &str = "domains.toml";

/// Where the state file of the data directory `data_dir` lives.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(FILE_NAME)
}

impl crate::editable::StateFile for DomainsFile {
	const FILE_NAME: &'static str = FILE_NAME;

	fn parse(text: &str) -> std::io::Result<Self> {
		DomainsFile::parse(text)
	}

	fn render(&self) -> std::io::Result<String> {
		DomainsFile::render(self)
	}

	fn seed(config: &crate::config::Config) -> Self {
		if config.domain_seed.captured {
			config.domain_seed.file()
		} else {
			config.domains_file()
		}
	}

	fn apply(config: &crate::config::Config, state: &Self) -> crate::config::Config {
		config.with_domains_file(state)
	}
}

#[cfg(test)]
mod tests;
