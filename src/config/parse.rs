use std::path::Path;

use super::env::expand_env;
use super::*;

impl Config {
	/// Raise a value below the least an RFC lets a server hold to that
	/// least, and say so. A file written before the floor existed then
	/// still starts the server; `epistle limits set` refuses the value.
	fn raise_to_floors(&mut self) -> Vec<String> {
		use crate::smtp::session::{MIN_MESSAGE_SIZE, MIN_MESSAGE_SIZE_REASON};
		let mut adjusted = Vec::new();
		if let Some(size) = self.max_message_size
			&& size != 0
			&& size < MIN_MESSAGE_SIZE as u64
		{
			adjusted.push(format!(
				"max_message_size is {size} bytes in the file, below the {MIN_MESSAGE_SIZE} \
				 the server needs ({MIN_MESSAGE_SIZE_REASON}); {MIN_MESSAGE_SIZE} bytes are \
				 used. Write it with `epistle limits set max-message-size 64k`"
			));
			self.max_message_size = Some(MIN_MESSAGE_SIZE as u64);
		}
		adjusted
	}

	/// Parse the text and apply what loading changes, without validating:
	/// the step `parse_text` and `parse_text_lenient` share.
	fn parse_unvalidated(raw: &str, path: &Path) -> Result<Self, ConfigError> {
		Self::parse_unvalidated_with(raw, path, true)
	}

	/// [`Self::parse_unvalidated`], laying the domain state file over the
	/// configuration file only when `overlay` is set.
	fn parse_unvalidated_with(raw: &str, path: &Path, overlay: bool) -> Result<Self, ConfigError> {
		let expanded = expand_env(raw)?;
		let mut config: Config =
			toml::from_str(&expanded).map_err(|source| ConfigError::Parse {
				path: path.to_path_buf(),
				source: Box::new(source),
			})?;
		config.mixed_case = config.normalize_identifiers();
		config.adjusted = config.raise_to_floors();
		let ignored = config.ignore_legacy_values();
		config.adjusted.extend(ignored);
		if overlay {
			config
				.overlay_domains_file()
				.map_err(ConfigError::Invalid)?;
		} else {
			config.domain_seed = crate::domain::state::DomainSeed::capture(&config);
		}
		Ok(config)
	}

	/// Load and validate the configuration file alone, without the domain
	/// state file of its data directory: what `epistle domain import` reads,
	/// so it can replace a state file that does not parse.
	pub(crate) fn load_ignoring_domains_file(path: &Path) -> Result<Self, ConfigError> {
		super::permissions::check_permissions(path, "config file")?;
		let raw = super::read::text(path)?;
		let config = Self::parse_unvalidated_with(&raw, path, false)?;
		config.validate()?;
		Ok(config)
	}

	/// Parse and validate text already read from a verified config descriptor.
	pub(crate) fn parse_text(raw: &str, path: &Path) -> Result<Self, ConfigError> {
		let config = Self::parse_unvalidated(raw, path)?;
		config.validate()?;
		Ok(config)
	}

	/// Parse text for a command that has to work on a file the validation
	/// refuses: it still has to be well-formed TOML with known keys, but a
	/// validation failure is kept in [`Config::validation_error`] instead of
	/// stopping the load.
	pub(crate) fn parse_text_lenient(raw: &str, path: &Path) -> Result<Self, ConfigError> {
		let mut config = Self::parse_unvalidated(raw, path)?;
		config.validation_error = config.validate().err().map(|error| error.to_string());
		Ok(config)
	}
}
