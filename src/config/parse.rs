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

	/// Parse and validate text already read from a verified config descriptor.
	pub(crate) fn parse_text(raw: &str, path: &Path) -> Result<Self, ConfigError> {
		let expanded = expand_env(raw)?;
		let mut config: Config =
			toml::from_str(&expanded).map_err(|source| ConfigError::Parse {
				path: path.to_path_buf(),
				source: Box::new(source),
			})?;
		config.mixed_case = config.normalize_identifiers();
		config.adjusted = config.raise_to_floors();
		config.validate()?;
		Ok(config)
	}
}
