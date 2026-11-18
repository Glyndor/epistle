//! What a scope adds to the server's attachment policy: only stronger
//! settings, merged to the strictest of every scope that applies.

use crate::config::{AttachmentMode, AttachmentScope, ContentAction, normalise_extension};

/// Settings that tighten a [`super::Policy`] for one message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overlay {
	/// A stronger action than the policy's `mode`.
	pub mode: Option<AttachmentMode>,
	/// A stronger action for macros.
	pub macros: Option<ContentAction>,
	/// A stronger action for encrypted archives.
	pub encrypted_archives: Option<ContentAction>,
	/// More dangerous extensions, normalised.
	pub block_extensions: Vec<String>,
	/// More blocked MIME types.
	pub block_mime_types: Vec<String>,
	/// A lower cap per attachment.
	pub max_attachment_bytes: Option<u64>,
}

impl Overlay {
	/// The overlay one scope declares.
	pub fn from_scope(scope: &AttachmentScope) -> Self {
		Self {
			mode: scope.mode,
			macros: scope.macros,
			encrypted_archives: scope.encrypted_archives,
			block_extensions: scope
				.block_extensions
				.iter()
				.map(|ext| normalise_extension(ext))
				.collect(),
			block_mime_types: scope
				.block_mime_types
				.iter()
				.map(|kind| kind.trim().to_ascii_lowercase())
				.collect(),
			max_attachment_bytes: scope.max_attachment_bytes,
		}
	}

	/// Whether it changes nothing.
	pub fn is_empty(&self) -> bool {
		*self == Self::default()
	}

	/// Keep the stronger of each setting of `self` and `other`, and every
	/// block of either.
	pub fn tighten(&mut self, other: &Self) {
		self.mode = self.mode.max(other.mode);
		self.macros = self.macros.max(other.macros);
		self.encrypted_archives = self.encrypted_archives.max(other.encrypted_archives);
		self.block_extensions
			.extend_from_slice(&other.block_extensions);
		self.block_extensions.sort();
		self.block_extensions.dedup();
		self.block_mime_types
			.extend_from_slice(&other.block_mime_types);
		self.block_mime_types.sort();
		self.block_mime_types.dedup();
		self.max_attachment_bytes = match (self.max_attachment_bytes, other.max_attachment_bytes) {
			(Some(a), Some(b)) => Some(a.min(b)),
			(a, b) => a.or(b),
		};
	}
}

/// Whether the declared `kind` (`type/subtype`) is named by `pattern`, which
/// is `type/subtype` or `type/*`.
pub(super) fn mime_matches(pattern: &str, kind: &str) -> bool {
	let kind = kind.trim().to_ascii_lowercase();
	match pattern.strip_suffix("/*") {
		Some(family) => kind
			.split_once('/')
			.is_some_and(|(declared, _)| declared == family),
		None => kind == pattern,
	}
}
