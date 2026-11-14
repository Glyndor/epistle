//! The errors loading or validating a configuration file can produce.

use std::path::PathBuf;

/// Errors produced while loading or validating a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// A file the configuration needed could not be read from disk: missing
	/// file, permission denied, or another I/O failure. The variant carries
	/// the path that was attempted, the underlying `std::io::Error`, and a
	/// short `kind` so the same variant can report both the config file
	/// itself and the `[database] password_file` secret (the operator reads
	/// a different fix for each one, but the I/O surface is the same).
	#[error("cannot read {kind} {path}: {source}")]
	Read {
		/// Path that failed to read.
		path: PathBuf,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
		/// What kind of file the rejected path was. `"config file"` for the
		/// loader, `"[database] password_file"` for the database password
		/// secret; both can fail with the same I/O error, but the operator
		/// reads a different fix.
		kind: &'static str,
	},
	/// The file was read but its contents are not valid TOML, or they contain
	/// an unknown key (the schema is `deny_unknown_fields`). Carries the path
	/// and the parser error.
	#[error("invalid TOML in {path}: {}", super::clip::lines(&.source.to_string()))]
	Parse {
		/// Path of the file that failed to parse.
		path: PathBuf,
		/// Underlying TOML deserialization error.
		source: Box<toml::de::Error>,
	},
	/// The configuration file is group- or world-readable (or writable): on
	/// Unix the loader requires mode `0600`. Carries the path, the
	/// observed permission bits (masked to the low 9) and a short
	/// description of what kind of file it was (so the same variant can be
	/// reused for the `[database] password_file` check, which produces the
	/// same kind of refusal for a different file).
	#[error(
		"{kind} {path} is group/world-accessible (mode {mode:#o}); restrict it to owner-only (0600 or 0400)"
	)]
	InsecurePermissions {
		/// Path whose permissions were rejected.
		path: PathBuf,
		/// Observed permission mode, masked to `0o777`.
		mode: u32,
		/// What kind of file the rejected path was. `"config file"` for the
		/// loader, `"[database] password_file"` for the database password
		/// secret; both can fail with the same bit pattern, but the operator
		/// reads a different fix.
		kind: &'static str,
	},
	/// The configuration referenced `${VAR}` for a variable that is not set
	/// in the process environment. Carries the variable name.
	#[error("config references undefined environment variable ${{{0}}}")]
	MissingEnv(String),
	/// A semantic validation check failed after parsing: cross-field
	/// consistency, an out-of-range number, or a malformed `${...}` token.
	#[error("invalid configuration: {0}")]
	Invalid(String),
}
