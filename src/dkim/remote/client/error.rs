//! What a remote signing call can end in, besides the signature.

use crate::dkim::remote::frame::Reason;

/// Why [`RemoteSigner`](super::RemoteSigner) returned no signature.
///
/// Only [`RemoteError::Unreadable`] and [`RemoteError::Refused`] are the
/// outcomes the in-process signer also has, where the message leaves
/// unsigned. [`RemoteError::Unavailable`] is not one of them: the signer
/// gave no answer that can be trusted, so the caller must not send the
/// message without its signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
	/// The message cannot be read into a header block (not exactly one
	/// `From` field, a header block that is not UTF-8, a field with no
	/// colon). Nothing was sent to the signer.
	#[error("the message cannot be read into a header block")]
	Unreadable,
	/// The signer read the request and refused this content: the `d=`
	/// domain, the header block, or a tag list that cannot be written.
	#[error("the signer refused the request: {0}")]
	Refused(Reason),
	/// No answer that can be trusted: the socket is missing, nobody
	/// listens on it, the connection closed early, the deadline passed,
	/// the answer was malformed, or the two sides disagree on the frame.
	#[error("the signer is unavailable: {0}")]
	Unavailable(String),
}
