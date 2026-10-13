//! Comment-preserving, validated edits to operator configuration files.

mod comments;
mod diff;
mod edits;
mod elements;
mod file;
mod lookup;
mod restart;
mod rules;
mod tables;

pub use restart::after_change;
pub(in crate::cli) use restart::{after_change_with, after_ports_change_with};
pub use rules::FieldChange;

use std::path::{Path, PathBuf};

use toml_edit::DocumentMut;

use crate::config::Config;

/// A configuration document read from a verified regular file.
pub struct ConfigDocument {
	path: PathBuf,
	original: String,
	document: DocumentMut,
	metadata: std::fs::Metadata,
}

/// Whether a validated edit replaced the configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
	/// The rendered bytes already matched the file.
	Unchanged,
	/// The validated document replaced the file atomically.
	Changed,
}

impl ConfigDocument {
	/// Read an owner-only regular file without following a leaf symlink.
	pub fn open(path: &Path) -> Result<Self, String> {
		let (original, metadata) = file::read(path)?;
		let document = original
			.parse()
			.map_err(|_| "cannot parse configuration TOML")?;
		Ok(Self {
			path: path.into(),
			original,
			document,
			metadata,
		})
	}

	/// Render the edited document, preserving untouched TOML syntax.
	pub fn render(&self) -> String {
		self.document.to_string()
	}

	/// Validate the rendered document with the server's normal loader rules.
	pub fn config(&self) -> Result<Config, String> {
		Config::parse_text(&self.render(), &self.path).map_err(|error| error.to_string())
	}

	/// Return a validated unified diff without creating or writing any file.
	pub fn dry_run(&self) -> Result<String, String> {
		self.config()?;
		Ok(diff::unified(&self.path, &self.original, &self.render()))
	}

	/// Validate before writing, then atomically replace changed bytes.
	pub fn commit(self) -> Result<Outcome, String> {
		self.config()?;
		let rendered = self.render();
		if rendered == self.original {
			return Ok(Outcome::Unchanged);
		}
		file::replace(&self.path, &self.original, &self.metadata, &rendered)?;
		Ok(Outcome::Changed)
	}
}

#[cfg(test)]
mod tests_dry_run;
#[cfg(test)]
mod tests_file;
#[cfg(test)]
mod tests_helpers;
#[cfg(test)]
mod tests_restart;
#[cfg(test)]
mod tests_rules;
#[cfg(test)]
mod tests_tables;
