//! Editable state kept in the data directory, next to `accounts.toml`, that
//! seeds from the configuration file and then replaces part of it.
//!
//! Some of what the configuration file declares has to change while
//! `/etc/epistle` stays read-only for the server: the hosted domains today
//! ([`crate::domain::state`]), and the `[[alias]]` entries next. Each such part
//! is one file in the data directory, a [`StateFile`], and this module is
//! what they share:
//!
//! - the configuration file is the seed: while the file does not exist, the
//!   configuration file's own entries are the state, and the first write
//!   copies them in ([`StateFile::seed`]);
//! - loading the configuration lays every state file over it
//!   ([`StateFile::apply`]), so every reader sees one configuration;
//! - [`commit()`] is the one write path: the cross-process lock of the file, a
//!   fresh read under it, the change, a check that the server would load the
//!   result, and an atomic owner-only rename, or nothing when nothing changed;
//! - [`LiveConfig`] is the configuration a running server applies, replaced
//!   when the file watcher sees a state file change or a route writes one.
//!
//! A new part implements [`StateFile`], adds its file to the watcher, and
//! has its command and routes describe their changes against it.

use std::path::{Path, PathBuf};

use crate::config::Config;

pub mod commit;
pub mod live;

pub use commit::{CommitError, Committed, commit, preview, seed};
pub use live::LiveConfig;

/// One part of the configuration kept as a file in the data directory.
pub trait StateFile: Clone + PartialEq + Default + std::fmt::Debug + Send + Sync + 'static {
	/// The file's name inside the data directory.
	const FILE_NAME: &'static str;

	/// Parse the text of the file.
	fn parse(text: &str) -> std::io::Result<Self>;

	/// The text written to disk.
	fn render(&self) -> std::io::Result<String>;

	/// The state the configuration file itself declares: what a missing file
	/// stands for, and what the first write starts from.
	fn seed(config: &Config) -> Self;

	/// `config` with `state` in place of the part this file holds, as a fresh
	/// load with `state` on disk would give it.
	fn apply(config: &Config, state: &Self) -> Config;
}

/// Where the state file `S` of the data directory `data_dir` lives.
pub fn path<S: StateFile>(data_dir: &Path) -> PathBuf {
	data_dir.join(S::FILE_NAME)
}
