//! What becomes of the blob a client names as a script's content, and how
//! the store's refusals are reported as JMAP errors (RFC 9661 section 2.4).
//!
//! A reason in an error is the store's: it names the line and the kind of
//! mistake and never repeats the script.

use serde_json::{Value, json};

use super::uploads::Found;
use crate::managesieve::store::{MAX_SCRIPT_BYTES, StoreError};

/// Why a blob cannot be used as a script.
pub(super) enum Unusable {
	/// No such blob in the account: a method error where there is no object
	/// to attach a SetError to, a `blobNotFound` SetError where there is.
	NotFound,
	/// The blob is not a script this server stores: a SetError.
	Error(Value),
}

impl Unusable {
	/// The SetError for `blob_id`.
	pub(super) fn into_set_error(self, blob_id: &str) -> Value {
		match self {
			Self::NotFound => json!({"type": "blobNotFound", "notFound": [blob_id]}),
			Self::Error(error) => error,
		}
	}
}

fn invalid_sieve(description: &str) -> Unusable {
	Unusable::Error(json!({"type": "invalidSieve", "description": description}))
}

/// The script text in a prefetched blob. The checks that depend on the
/// store (grammar, extensions, limits on names and counts) are the store's.
pub(super) fn script_text(found: Found<'_>) -> Result<String, Unusable> {
	let upload = match found {
		Found::Blob(upload) => upload,
		Found::OverBudget => return Err(Unusable::Error(json!({"type": "tooLarge"}))),
		Found::Missing => return Err(Unusable::NotFound),
	};
	if upload.data.len() > MAX_SCRIPT_BYTES {
		return Err(Unusable::Error(json!({"type": "tooLarge"})));
	}
	// RFC 9661 section 2.2: a script is UTF-8 and at least one character.
	let text = std::str::from_utf8(&upload.data)
		.map_err(|_| invalid_sieve("script is not valid UTF-8"))?;
	if text.is_empty() {
		return Err(invalid_sieve("script is empty"));
	}
	Ok(text.to_string())
}

/// A store refusal as a SetError. `AlreadyExists` has no `existingId` here:
/// only the caller can look it up.
pub(super) fn set_error(error: &StoreError) -> Value {
	match error {
		StoreError::InvalidName => json!({"type": "invalidProperties", "properties": ["name"]}),
		StoreError::NoSuchScript => json!({"type": "notFound"}),
		StoreError::AlreadyExists => json!({"type": "alreadyExists"}),
		StoreError::ActiveScript => json!({"type": "sieveIsActive"}),
		StoreError::InvalidScript(reason) => {
			json!({"type": "invalidSieve", "description": reason})
		}
		StoreError::TooLarge => json!({"type": "tooLarge"}),
		StoreError::TooManyScripts => json!({"type": "overQuota"}),
		StoreError::Io => json!({"type": "serverFail"}),
	}
}
