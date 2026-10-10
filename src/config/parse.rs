use super::*;

impl Config {
	/// Parse and validate text already read from a verified config descriptor.
	pub(crate) fn parse_text(raw: &str, path: &Path) -> Result<Self, ConfigError> {
		let expanded = expand_env(raw)?;
		let config: Config = toml::from_str(&expanded).map_err(|source| ConfigError::Parse {
			path: path.to_path_buf(),
			source: Box::new(source),
		})?;
		config.validate()?;
		Ok(config)
	}
}
