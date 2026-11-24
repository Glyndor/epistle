//! The shape of `<data_dir>/address-aliases.toml` and how it is read.
//!
//! ```toml
//! seed_digest = "sha256:..."
//!
//! [[alias]]
//! address = "team@example.org"
//! members = ["alice@example.org", "bob@example.org"]
//! hidden = true
//! ```
//!
//! Each `[[alias]]` is the table the configuration file spells, with the same
//! fields and the same checks at load.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::Alias;
use crate::util::address::normalize;

/// The whole state file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasesFile {
	/// The digest of the `[[alias]]` entries the configuration file declared
	/// when this file was made, so a later edit of them can be noticed.
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub seed_digest: String,
	/// The aliases, in the order they were added.
	#[serde(default, rename = "alias")]
	pub aliases: Vec<Alias>,
}

impl AliasesFile {
	/// Parse the text of the file.
	pub fn parse(text: &str) -> std::io::Result<Self> {
		toml::from_str(text).map_err(|error| {
			std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
		})
	}

	/// The text written to disk.
	pub fn render(&self) -> std::io::Result<String> {
		let body = toml::to_string_pretty(self).map_err(|error| {
			std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
		})?;
		Ok(format!("{HEADER}{body}"))
	}

	/// Read the file at `path`. `Ok(None)` when it does not exist.
	pub fn read(path: &Path) -> std::io::Result<Option<Self>> {
		match std::fs::read_to_string(path) {
			Ok(text) => Self::parse(&text).map(Some),
			Err(error)
				if matches!(
					error.kind(),
					std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
				) =>
			{
				Ok(None)
			}
			Err(error) => Err(error),
		}
	}

	/// The alias at `address`, whatever its spelling.
	pub fn alias(&self, address: &str) -> Option<&Alias> {
		let wanted = normalize(address);
		self.aliases
			.iter()
			.find(|alias| normalize(&alias.address) == wanted)
	}

	/// [`Self::alias`], to change it.
	pub fn alias_mut(&mut self, address: &str) -> Option<&mut Alias> {
		let wanted = normalize(address);
		self.aliases
			.iter_mut()
			.find(|alias| normalize(&alias.address) == wanted)
	}
}

/// The comment the file starts with, for whoever opens it.
const HEADER: &str = "# The address aliases of this server. `epistle alias` and the\n\
	# /api/v1/aliases routes write this file and the server reloads it within\n\
	# seconds. While it exists, the [[alias]] tables of the configuration file\n\
	# are not read.\n\n";
