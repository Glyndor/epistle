//! The signer's side of the socket: answer each request with the key
//! holder, after checking it.

mod admit;
mod socket;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::frame::{MAX_REQUEST_BYTES, ReadError, Reason, SignResponse, read_frame};
use crate::dkim::{KeyHolder, Refusal};

pub(crate) use admit::admit;
pub use socket::bind;

/// How long one exchange may take on the server, from the accept to the
/// last byte of the answer: reading the request, signing, writing.
pub const SERVER_DEADLINE: Duration = Duration::from_secs(5);
/// How many exchanges run at once. A connection that arrives with every
/// slot busy is closed unanswered, which its client reads as an
/// unavailable signer.
pub const MAX_CONNECTIONS: usize = 32;

/// A signing service: a [`KeyHolder`] behind a Unix socket.
pub struct SignerServer {
	holder: Arc<dyn KeyHolder>,
	deadline: Duration,
	slots: Arc<Semaphore>,
}

impl SignerServer {
	/// A server that signs with `holder`, with [`SERVER_DEADLINE`] and
	/// [`MAX_CONNECTIONS`].
	pub fn new(holder: Arc<dyn KeyHolder>) -> Self {
		SignerServer {
			holder,
			deadline: SERVER_DEADLINE,
			slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
		}
	}

	/// Replace the deadline on one exchange.
	pub fn with_deadline(mut self, deadline: Duration) -> Self {
		self.deadline = deadline;
		self
	}

	/// Replace how many exchanges run at once.
	pub fn with_max_connections(mut self, connections: usize) -> Self {
		self.slots = Arc::new(Semaphore::new(connections));
		self
	}

	/// Answer connections on `listener` until the task running this is
	/// dropped. One request and one answer per connection.
	pub async fn serve(self, listener: UnixListener) {
		let server = Arc::new(self);
		loop {
			let stream = match listener.accept().await {
				Ok((stream, _)) => stream,
				Err(error) => {
					tracing::warn!(%error, "DKIM signer: accept failed");
					// An accept that fails at once (no descriptor left)
					// would spin the loop without a pause.
					tokio::time::sleep(Duration::from_millis(100)).await;
					continue;
				}
			};
			let Ok(slot) = server.slots.clone().try_acquire_owned() else {
				tracing::warn!(
					"DKIM signer: every connection slot is busy; a connection was closed unanswered"
				);
				continue;
			};
			let server = server.clone();
			tokio::spawn(async move {
				server.exchange(stream).await;
				drop(slot);
			});
		}
	}

	/// One exchange under the deadline. A client that has not finished by
	/// then is cut off, whatever it was doing.
	async fn exchange(&self, mut stream: UnixStream) {
		match tokio::time::timeout(self.deadline, self.answer_on(&mut stream)).await {
			Ok(Ok(())) => {}
			Ok(Err(error)) => tracing::debug!(%error, "DKIM signer: the exchange failed"),
			Err(_) => tracing::warn!(
				deadline_ms = self.deadline.as_millis(),
				"DKIM signer: a client did not finish its exchange within the deadline; it was cut off"
			),
		}
	}

	async fn answer_on(&self, stream: &mut UnixStream) -> std::io::Result<()> {
		let answer = match read_frame(stream, MAX_REQUEST_BYTES).await {
			Ok(body) => self.answer(&body).await,
			Err(ReadError::TooLarge(announced)) => {
				tracing::warn!(
					announced,
					"DKIM signer: refused a request larger than it accepts"
				);
				Some(SignResponse::Refused(Reason::TooLarge))
			}
			Err(ReadError::Io(error)) => return Err(error),
		};
		// No answer at all when signing failed inside the holder: the
		// client must read that as an unavailable signer, never as a
		// refusal of this message.
		let Some(answer) = answer else {
			return Ok(());
		};
		stream.write_all(&answer.encode()).await?;
		stream.shutdown().await
	}

	/// The answer to one request body, `None` when the key holder failed
	/// without answering (it panicked).
	pub(super) async fn answer(&self, body: &[u8]) -> Option<SignResponse> {
		let request = match admit(body) {
			Ok(request) => request,
			Err(reason) => {
				tracing::warn!(%reason, "DKIM signer: refused a request");
				return Some(SignResponse::Refused(reason));
			}
		};
		let holder = self.holder.clone();
		let signed =
			tokio::task::spawn_blocking(move || holder.sign_block(&request.domain, &request.block))
				.await;
		match signed {
			Ok(Ok(fields)) => Some(SignResponse::Signed(fields)),
			Ok(Err(Refusal::Malformed(_))) => Some(SignResponse::Refused(Reason::Block)),
			Ok(Err(Refusal::Unsignable)) => Some(SignResponse::Refused(Reason::Unsignable)),
			Err(error) => {
				tracing::error!(%error, "DKIM signer: the key holder failed while signing");
				None
			}
		}
	}
}

#[cfg(test)]
pub(crate) use admit::is_host_name;
