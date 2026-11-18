//! The frame a DKIM signing request and its answer travel in.
//!
//! Every frame is a 4-byte big-endian length followed by that many bytes
//! of body. A request body is the version byte, the operation byte, and
//! four fields: the `d=` domain, the `h=` names, the canonical header
//! lines, and the 32-byte body hash. An answer body is the version byte, a
//! status byte, and one field: the `DKIM-Signature` fields when the status
//! is [`STATUS_SIGNED`], one [`Reason`] byte when it is
//! [`STATUS_REFUSED`]. A field is a 4-byte big-endian length followed by
//! its bytes. Nothing may follow the last field.
//!
//! Each field has a cap and so does each frame, and the length prefix is
//! checked against the cap before anything is allocated: the decoder reads
//! input from a process that may be compromised, on both sides.

mod fields;
mod io;
mod request;
mod response;

pub(crate) use io::{ReadError, read_frame};
pub(crate) use request::SignRequest;
pub(crate) use response::SignResponse;

/// The only version of the frame this build speaks.
pub const VERSION: u8 = 1;
/// The operation byte of a DKIM signing request.
pub const OP_SIGN_DKIM: u8 = 1;
/// The status byte of an answer that carries the signature fields.
pub const STATUS_SIGNED: u8 = 0;
/// The status byte of an answer that carries a [`Reason`].
pub const STATUS_REFUSED: u8 = 1;

/// The longest `d=` domain: the longest DNS name.
pub const MAX_DOMAIN_BYTES: usize = 253;
/// The longest `h=` value.
pub const MAX_NAMES_BYTES: usize = 64 * 1024;
/// The longest canonical header block, the same cap ARC puts on the header
/// block it reads (`src/arc/ams.rs`).
pub const MAX_CANONICAL_BYTES: usize = 2 * 1024 * 1024;
/// The length of a SHA-256 body hash.
pub const BODY_HASH_BYTES: usize = 32;
/// The longest request body: every field at its cap, their length
/// prefixes, the version and the operation.
pub const MAX_REQUEST_BYTES: usize =
	2 + 4 * 4 + MAX_DOMAIN_BYTES + MAX_NAMES_BYTES + MAX_CANONICAL_BYTES + BODY_HASH_BYTES;
/// The longest signature fields an answer may carry: two signatures, each
/// repeating an `h=` at its cap with the folding around it.
pub const MAX_SIGNATURE_BYTES: usize = 4 * MAX_NAMES_BYTES;
/// The longest answer body.
pub const MAX_RESPONSE_BYTES: usize = 2 + 4 + MAX_SIGNATURE_BYTES;

/// Why the signer refused a request, as the answer carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(u8)]
pub enum Reason {
	/// The request is not a frame of this format: truncated, a field over
	/// its cap, bytes after the last field, or text that is not UTF-8.
	#[error("the request is not a well-formed frame")]
	Frame = 1,
	/// The request names a version this signer does not speak.
	#[error("the request names an unsupported version")]
	Version = 2,
	/// The request names an operation this signer does not perform.
	#[error("the request names an unknown operation")]
	Operation = 3,
	/// The length prefix of the request is over [`MAX_REQUEST_BYTES`].
	#[error("the request is larger than the signer accepts")]
	TooLarge = 4,
	/// The `d=` domain is not a host name.
	#[error("the d= domain is not a host name")]
	Domain = 5,
	/// The header block failed [`HeaderBlock::check`](crate::dkim::HeaderBlock::check).
	#[error("the header block is malformed")]
	Block = 6,
	/// The tag list cannot be written for this domain and these names.
	#[error("the signature cannot be written for this domain and these names")]
	Unsignable = 7,
}

impl Reason {
	/// The reason a byte names, `None` for a byte that names none.
	pub fn from_byte(byte: u8) -> Option<Self> {
		Some(match byte {
			1 => Reason::Frame,
			2 => Reason::Version,
			3 => Reason::Operation,
			4 => Reason::TooLarge,
			5 => Reason::Domain,
			6 => Reason::Block,
			7 => Reason::Unsignable,
			_ => return None,
		})
	}

	/// Whether the refusal is about the frame rather than the content: the
	/// two sides do not agree on the format, so the answer says nothing
	/// about whether this message can be signed.
	pub fn is_about_the_frame(self) -> bool {
		matches!(
			self,
			Reason::Frame | Reason::Version | Reason::Operation | Reason::TooLarge
		)
	}
}

/// Why a frame body could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
	/// The body ends before a byte or a field it must carry.
	#[error("the frame ends early")]
	Truncated,
	/// A field is longer than its cap, or the frame than the frame cap.
	#[error("a field or the frame is over its cap")]
	TooLong,
	/// Bytes follow the last field.
	#[error("bytes follow the last field")]
	Trailing,
	/// The version byte is not [`VERSION`].
	#[error("unsupported version {0}")]
	Version(u8),
	/// The operation byte is not one this format defines.
	#[error("unknown operation {0}")]
	Operation(u8),
	/// The status byte or the reason byte of an answer is not one this
	/// format defines.
	#[error("unknown status or reason {0}")]
	Status(u8),
	/// A text field is not UTF-8.
	#[error("a text field is not UTF-8")]
	NotUtf8,
	/// The body hash is not [`BODY_HASH_BYTES`] long.
	#[error("the body hash is not 32 bytes")]
	BodyHash,
}

/// Prefix `body` with its length, the outer layer of every frame.
fn framed(body: Vec<u8>) -> Vec<u8> {
	let mut frame = Vec::with_capacity(4 + body.len());
	frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
	frame.extend_from_slice(&body);
	frame
}
