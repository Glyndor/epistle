//! Laying `<data_dir>/address-aliases.toml` over the configuration file.
//!
//! While the state file exists, the aliases are the file's, whatever the
//! `[[alias]]` tables of the configuration file say. The seed, the
//! configuration file's own tables, is taken once when the file is loaded and
//! before the overlay, so a reload of the state file starts again from the
//! same values.

use crate::config::{Alias, Config};

use super::file::AliasesFile;

/// A digest of the `[[alias]]` tables, independent of their order and of the
/// order of the addresses in them, so an edit of the configuration file after
/// the state file was made from it shows as a different digest.
pub fn digest(aliases: &[Alias]) -> String {
	let mut lines: Vec<String> = aliases
		.iter()
		.map(|alias| {
			let sorted = |list: &[String]| {
				let mut list: Vec<String> =
					list.iter().map(|a| a.trim().to_ascii_lowercase()).collect();
				list.sort();
				list.join(",")
			};
			format!(
				"{}|{}|{}|{}|{}",
				alias.address.trim().to_ascii_lowercase(),
				sorted(&alias.members),
				sorted(&alias.senders),
				alias.hidden,
				alias.list_id.as_deref().unwrap_or("")
			)
		})
		.collect();
	lines.sort();
	let digest = ring::digest::digest(&ring::digest::SHA256, lines.join("\n").as_bytes());
	let hex: String = digest
		.as_ref()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	format!("sha256:{hex}")
}

impl Config {
	/// Take the seed of a configuration loaded from a file and lay the state
	/// file of its data directory over it. A missing state file leaves the
	/// aliases as the configuration file declared them. A state file that
	/// cannot be read or parsed is an error: the server must not start with
	/// aliases it did not mean.
	pub(crate) fn overlay_aliases_file(&mut self) -> Result<(), String> {
		self.alias_seed = Some(self.alias.clone());
		if !self.data_dir.is_absolute() {
			return Ok(());
		}
		let path = super::path(&self.data_dir);
		let file = AliasesFile::read(&path).map_err(|error| {
			format!(
				"{}: {error}; fix the file, or move it away to use the [[alias]] tables of \
				 the configuration file",
				path.display()
			)
		})?;
		let Some(file) = file else {
			return Ok(());
		};
		if !file.seed_digest.is_empty() && file.seed_digest != digest(&self.alias) {
			self.adjusted.push(format!(
				"the [[alias]] tables of the configuration file changed after {} was made \
				 from them; the server uses {}, and `epistle alias` and /api/v1/aliases \
				 edit it",
				path.display(),
				path.display()
			));
		}
		self.alias = file.aliases;
		Ok(())
	}

	/// This configuration with `file` as its aliases, as a fresh load with
	/// `file` on disk would give it.
	pub fn with_aliases_file(&self, file: &AliasesFile) -> Config {
		let mut next = self.clone();
		if next.alias_seed.is_none() {
			next.alias_seed = Some(next.alias.clone());
		}
		next.alias = file.aliases.clone();
		next
	}

	/// The aliases the configuration file declares, as a state file: what a
	/// missing file stands for and what the first write starts from.
	pub fn aliases_seed_file(&self) -> AliasesFile {
		let aliases = self
			.alias_seed
			.clone()
			.unwrap_or_else(|| self.alias.clone());
		AliasesFile {
			seed_digest: if self.alias_seed.is_some() {
				digest(&aliases)
			} else {
				String::new()
			},
			aliases,
		}
	}
}
