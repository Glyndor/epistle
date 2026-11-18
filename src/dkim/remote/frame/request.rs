//! The request frame: sign this header block for this domain.

use super::fields::{self, Fields};
use super::{
	BODY_HASH_BYTES, FrameError, MAX_CANONICAL_BYTES, MAX_DOMAIN_BYTES, MAX_NAMES_BYTES,
	OP_SIGN_DKIM, VERSION, framed,
};
use crate::dkim::HeaderBlock;

/// A DKIM signing request as it crosses the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignRequest {
	/// The `d=` domain, as the requester picked it.
	pub(crate) domain: String,
	/// What the signature covers, minus the tag list the signer writes.
	pub(crate) block: HeaderBlock,
}

impl SignRequest {
	/// The whole frame, length prefix included. Refused when a field is
	/// over its cap, so a request the signer would refuse for its size is
	/// never sent.
	pub(crate) fn encode(&self) -> Result<Vec<u8>, FrameError> {
		let mut body = vec![VERSION, OP_SIGN_DKIM];
		fields::put(&mut body, self.domain.as_bytes(), MAX_DOMAIN_BYTES)?;
		fields::put(&mut body, self.block.names.as_bytes(), MAX_NAMES_BYTES)?;
		fields::put(
			&mut body,
			self.block.canonical.as_bytes(),
			MAX_CANONICAL_BYTES,
		)?;
		fields::put(&mut body, &self.block.body_hash, BODY_HASH_BYTES)?;
		Ok(framed(body))
	}

	/// Decode a request body (the frame without its length prefix). The
	/// version is read first, so a frame of another version is refused for
	/// its version and not for a layout this build does not know.
	pub(crate) fn decode(body: &[u8]) -> Result<Self, FrameError> {
		let mut fields = Fields::new(body);
		let version = fields.byte()?;
		if version != VERSION {
			return Err(FrameError::Version(version));
		}
		let operation = fields.byte()?;
		if operation != OP_SIGN_DKIM {
			return Err(FrameError::Operation(operation));
		}
		let domain = fields.text(MAX_DOMAIN_BYTES)?.to_string();
		let names = fields.text(MAX_NAMES_BYTES)?.to_string();
		let canonical = fields.text(MAX_CANONICAL_BYTES)?.to_string();
		let body_hash = fields
			.field(BODY_HASH_BYTES)?
			.try_into()
			.map_err(|_| FrameError::BodyHash)?;
		fields.end()?;
		Ok(SignRequest {
			domain,
			block: HeaderBlock {
				names,
				canonical,
				body_hash,
			},
		})
	}
}
