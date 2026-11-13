//! The answer frame: the signature fields, or why there are none.

use super::fields::{self, Fields};
use super::{
	FrameError, MAX_SIGNATURE_BYTES, Reason, STATUS_REFUSED, STATUS_SIGNED, VERSION, framed,
};

/// The signer's answer as it crosses the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignResponse {
	/// The `DKIM-Signature` fields to prepend, folded and CRLF-terminated.
	Signed(String),
	/// The signer refused the request.
	Refused(Reason),
}

impl SignResponse {
	/// The whole frame, length prefix included. A signature over
	/// [`MAX_SIGNATURE_BYTES`] is answered as [`Reason::Unsignable`]: the
	/// client would refuse it anyway, and a refusal says why.
	pub(crate) fn encode(&self) -> Vec<u8> {
		let mut body = vec![VERSION];
		match self {
			SignResponse::Signed(fields_text) => {
				body.push(STATUS_SIGNED);
				if fields::put(&mut body, fields_text.as_bytes(), MAX_SIGNATURE_BYTES).is_err() {
					return SignResponse::Refused(Reason::Unsignable).encode();
				}
			}
			SignResponse::Refused(reason) => {
				body.push(STATUS_REFUSED);
				// One byte always fits a cap of one.
				let _ = fields::put(&mut body, &[*reason as u8], 1);
			}
		}
		framed(body)
	}

	/// Decode an answer body (the frame without its length prefix).
	pub(crate) fn decode(body: &[u8]) -> Result<Self, FrameError> {
		let mut fields = Fields::new(body);
		let version = fields.byte()?;
		if version != VERSION {
			return Err(FrameError::Version(version));
		}
		let answer = match fields.byte()? {
			STATUS_SIGNED => SignResponse::Signed(fields.text(MAX_SIGNATURE_BYTES)?.to_string()),
			STATUS_REFUSED => {
				let [byte] = fields.field(1)? else {
					return Err(FrameError::Truncated);
				};
				SignResponse::Refused(Reason::from_byte(*byte).ok_or(FrameError::Status(*byte))?)
			}
			other => return Err(FrameError::Status(other)),
		};
		fields.end()?;
		Ok(answer)
	}
}
