//! The reading side of the socket: send the header block, read back the
//! signature or why there is none.

mod error;

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use super::frame::{MAX_RESPONSE_BYTES, ReadError, SignRequest, SignResponse, read_frame};
use crate::dkim::HeaderBlock;

pub use error::RemoteError;

/// How long one call may take on the client, from the connect to the last
/// byte of the answer.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// A client of a [`SignerServer`](super::SignerServer) on a Unix socket.
///
/// It does not implement [`KeyHolder`](crate::dkim::KeyHolder) on purpose:
/// the in-process path turns every error into "send unsigned", and an
/// unavailable signer must not take that path
/// ([`RemoteError::Unavailable`]).
#[derive(Debug, Clone)]
pub struct RemoteSigner {
	socket: PathBuf,
	deadline: Duration,
}

impl RemoteSigner {
	/// A client of the signer listening on `socket`, with
	/// [`DEFAULT_DEADLINE`].
	pub fn new(socket: impl Into<PathBuf>) -> Self {
		RemoteSigner {
			socket: socket.into(),
			deadline: DEFAULT_DEADLINE,
		}
	}

	/// Replace the deadline on one call.
	pub fn with_deadline(mut self, deadline: Duration) -> Self {
		self.deadline = deadline;
		self
	}

	/// Read `raw` into a header block here and have the signer sign it for
	/// `domain`. The body never leaves this process.
	pub async fn sign(&self, domain: &str, raw: &[u8]) -> Result<String, RemoteError> {
		let block = HeaderBlock::from_message(raw).ok_or(RemoteError::Unreadable)?;
		self.sign_block(domain, &block).await
	}

	/// Have the signer sign `block` for `domain`, and return the
	/// `DKIM-Signature` fields to prepend. Every outcome but the signature
	/// is logged: [`RemoteError::Unavailable`] as an error, a refusal as a
	/// warning.
	pub async fn sign_block(
		&self,
		domain: &str,
		block: &HeaderBlock,
	) -> Result<String, RemoteError> {
		let request = SignRequest {
			domain: domain.to_string(),
			block: block.clone(),
		};
		let outcome = match request.encode() {
			Ok(frame) => self.exchange(&frame).await,
			Err(error) => Err(RemoteError::Unavailable(format!(
				"the request does not fit the frame: {error}"
			))),
		};
		match &outcome {
			Ok(_) | Err(RemoteError::Unreadable) => {}
			Err(RemoteError::Refused(reason)) => {
				tracing::warn!(%domain, %reason, "DKIM signer refused to sign; the message is not signed");
			}
			Err(RemoteError::Unavailable(cause)) => {
				tracing::error!(
					socket = %self.socket.display(),
					%domain,
					%cause,
					"DKIM signer unavailable; the message is not signed and must not be sent without its signature"
				);
			}
		}
		outcome
	}

	/// Send one request frame and read the answer, all under the deadline.
	async fn exchange(&self, frame: &[u8]) -> Result<String, RemoteError> {
		let call = async {
			let mut stream = UnixStream::connect(&self.socket).await?;
			stream.write_all(frame).await?;
			stream.shutdown().await?;
			read_frame(&mut stream, MAX_RESPONSE_BYTES).await
		};
		let body = match tokio::time::timeout(self.deadline, call).await {
			Ok(Ok(body)) => body,
			Ok(Err(ReadError::Io(error))) => return Err(unavailable(error)),
			Ok(Err(error @ ReadError::TooLarge(_))) => return Err(unavailable(error)),
			Err(_) => {
				return Err(RemoteError::Unavailable(format!(
					"no answer within {} ms",
					self.deadline.as_millis()
				)));
			}
		};
		match SignResponse::decode(&body) {
			Ok(SignResponse::Signed(fields)) if signature_fields(&fields) => Ok(fields),
			Ok(SignResponse::Signed(_)) => Err(RemoteError::Unavailable(
				"the answer is not DKIM-Signature fields".into(),
			)),
			Ok(SignResponse::Refused(reason)) if reason.is_about_the_frame() => Err(
				RemoteError::Unavailable(format!("the signer did not take the frame: {reason}")),
			),
			Ok(SignResponse::Refused(reason)) => Err(RemoteError::Refused(reason)),
			Err(error) => Err(unavailable(format!("malformed answer: {error}"))),
		}
	}
}

fn unavailable(cause: impl std::fmt::Display) -> RemoteError {
	RemoteError::Unavailable(cause.to_string())
}

/// Whether `text` is one or more folded `DKIM-Signature` fields and
/// nothing else: every line ends in CRLF, every line that is not a
/// continuation starts a `DKIM-Signature` field, and no line is empty, so
/// the answer cannot end the header block or add a field of its own.
fn signature_fields(text: &str) -> bool {
	!text.is_empty()
		&& text.ends_with("\r\n")
		&& text.split_inclusive("\r\n").all(|line| {
			let Some(content) = line.strip_suffix("\r\n") else {
				return false;
			};
			!content.is_empty()
				&& !content.contains(['\r', '\n'])
				&& (content.starts_with([' ', '\t']) || content.starts_with("DKIM-Signature:"))
		})
		&& text.starts_with("DKIM-Signature:")
}
