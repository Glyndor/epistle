//! What the signer checks on a request before the key holder sees it.
//!
//! None of it trusts the socket: a request that came in on the signer's
//! own socket is decoded and checked exactly as one from anywhere else.

use crate::dkim::remote::frame::{FrameError, Reason, SignRequest};

/// Decode `body` and check it: the frame, the `d=` domain and the header
/// block. The [`Reason`] is what the answer carries back.
pub(crate) fn admit(body: &[u8]) -> Result<SignRequest, Reason> {
	let request = SignRequest::decode(body).map_err(|error| match error {
		FrameError::Version(_) => Reason::Version,
		FrameError::Operation(_) => Reason::Operation,
		_ => Reason::Frame,
	})?;
	if !is_host_name(&request.domain) {
		return Err(Reason::Domain);
	}
	request.block.check().map_err(|_| Reason::Block)?;
	Ok(request)
}

/// Whether `domain` is a host name: dot-separated labels of ASCII letters,
/// digits and hyphens, each 1 to 63 bytes, 253 bytes in all. The tag list
/// writes `d=` verbatim, so anything else (`;`, `=`, whitespace, a line
/// break, an empty label) would let the requester write tags of its own.
/// Case is kept: the in-process signer writes `d=` as it is given, and the
/// signature has to be the same bytes.
pub(crate) fn is_host_name(domain: &str) -> bool {
	!domain.is_empty()
		&& domain.len() <= crate::dkim::remote::frame::MAX_DOMAIN_BYTES
		&& domain.split('.').all(|label| {
			(1..=63).contains(&label.len())
				&& label
					.bytes()
					.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
		})
}
