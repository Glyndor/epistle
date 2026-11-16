//! The `[attachments]` section: what to do with attachments that are not
//! what they claim to be.

use serde::Deserialize;

use super::{Config, ConfigError};

/// Longest extension accepted in `block_extensions` or `allow_extensions`.
pub const MAX_EXTENSION_LEN: usize = 32;
/// Most entries in either list.
pub const MAX_EXTENSIONS: usize = 256;

/// What a finding does to the message.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentMode {
	/// No inspection at all.
	Off,
	/// Deliver with an `X-Epistle-Attachment-Warning` header. The default
	/// when the section is absent, so an upgrade only adds a header.
	#[default]
	Flag,
	/// Deliver to the Rejects mailbox, with the warning header.
	Quarantine,
	/// Refuse during SMTP with `550 5.7.1 attachment type not accepted`.
	Reject,
}

/// What macros or encrypted archives do, capped by [`AttachmentMode`].
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ContentAction {
	/// Not a finding.
	Allow,
	/// Flag only.
	#[default]
	Flag,
	/// Quarantine (or flag, when the mode is `flag`).
	Quarantine,
}

/// The `[attachments]` section.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Attachments {
	/// What a finding does. Absent means `flag`; `epistle init` writes
	/// `quarantine`.
	pub mode: AttachmentMode,
	/// Extensions treated as dangerous on top of the built-in list, without
	/// the dot.
	pub block_extensions: Vec<String>,
	/// Extensions removed from the dangerous list. They still count when
	/// the content itself is an executable.
	pub allow_extensions: Vec<String>,
	/// Office documents with VBA macros.
	pub macros: ContentAction,
	/// Archives with encrypted entries, which no scanner can read.
	pub encrypted_archives: ContentAction,
	/// Largest single attachment, in bytes after decoding. Absent means no
	/// cap. A larger one is a finding, handled as `mode` says.
	pub max_attachment_bytes: Option<u64>,
	/// Declared MIME types (`application/pdf`, or `image/*` for a family)
	/// that are a finding. Empty by default.
	pub block_mime_types: Vec<String>,
}

/// `value` as the extension lists store it: no leading dot, lower case.
pub fn normalise_extension(value: &str) -> String {
	value.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// Whether `value` is a usable extension: 1 to 32 ASCII letters, digits,
/// `-` or `_`, after an optional leading dot.
pub fn valid_extension(value: &str) -> bool {
	let value = normalise_extension(value);
	!value.is_empty()
		&& value.len() <= MAX_EXTENSION_LEN
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether `value` is `type/subtype` or `type/*`: lower case letters,
/// digits and `.+-_` in each part, up to 127 characters.
pub fn valid_mime_pattern(value: &str) -> bool {
	let token = |part: &str| {
		!part.is_empty()
			&& part.bytes().all(|byte| {
				byte.is_ascii_lowercase()
					|| byte.is_ascii_digit()
					|| matches!(byte, b'.' | b'+' | b'-' | b'_')
			})
	};
	value.len() <= 127
		&& value
			.split_once('/')
			.is_some_and(|(kind, sub)| token(kind) && (sub == "*" || token(sub)))
}

impl Config {
	pub(super) fn validate_attachments(&self) -> Result<(), ConfigError> {
		let section = &self.attachments;
		for (key, list) in [
			("block_extensions", &section.block_extensions),
			("allow_extensions", &section.allow_extensions),
		] {
			if list.len() > MAX_EXTENSIONS {
				return Err(ConfigError::Invalid(format!(
					"[attachments] {key} has more than {MAX_EXTENSIONS} entries"
				)));
			}
			if let Some(bad) = list.iter().find(|value| !valid_extension(value)) {
				return Err(ConfigError::Invalid(format!(
					"[attachments] {key}: {bad:?} is not an extension (letters, digits, - and _, up to {MAX_EXTENSION_LEN})"
				)));
			}
		}
		if let Some(always) = section.allow_extensions.iter().find(|allow| {
			crate::antispam::attachments::rules::ALWAYS_DANGEROUS
				.contains(&normalise_extension(allow).as_str())
		}) {
			return Err(ConfigError::Invalid(format!(
				"[attachments] allow_extensions: {} is always dangerous and cannot be allowed",
				normalise_extension(always)
			)));
		}
		if let Some(both) = section.block_extensions.iter().find(|block| {
			section
				.allow_extensions
				.iter()
				.any(|allow| normalise_extension(allow) == normalise_extension(block))
		}) {
			return Err(ConfigError::Invalid(format!(
				"[attachments] {} is in both block_extensions and allow_extensions",
				normalise_extension(both)
			)));
		}
		if section.max_attachment_bytes == Some(0) {
			return Err(ConfigError::Invalid(
				"[attachments] max_attachment_bytes must be > 0".into(),
			));
		}
		if section.block_mime_types.len() > MAX_EXTENSIONS {
			return Err(ConfigError::Invalid(format!(
				"[attachments] block_mime_types has more than {MAX_EXTENSIONS} entries"
			)));
		}
		if let Some(bad) = section
			.block_mime_types
			.iter()
			.find(|value| !valid_mime_pattern(value))
		{
			return Err(ConfigError::Invalid(format!(
				"[attachments] block_mime_types: {bad:?} is not a type/subtype or type/*"
			)));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
