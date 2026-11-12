//! What an S3 endpoint we do not control may make this process spend.
//!
//! The endpoint is a remote peer. It can accept the request and never answer,
//! trickle a body one byte at a time, declare a body no object can have, redirect
//! in a circle, or page a listing forever. Each is bounded here, so a hostile or
//! broken endpoint costs one failed call instead of a task that never returns
//! or memory that grows with what the peer chooses to send.

use std::time::Duration;

use super::BlobError;

/// The budget of one backend. `S3Backend::new` uses [`Limits::DEFAULT`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
	/// Time to open the TCP (and TLS) connection.
	pub(crate) connect: Duration,
	/// Longest silence while waiting for the response or between body reads.
	pub(crate) read: Duration,
	/// Wall-clock time for a whole request, body included. It is what stops a
	/// peer that sends just often enough to beat `read`.
	pub(crate) total: Duration,
	/// Most bytes accepted as one object body.
	pub(crate) object: u64,
	/// Most bytes accepted as one `ListObjectsV2` page.
	pub(crate) listing: u64,
	/// Most pages a listing walk follows.
	pub(crate) pages: usize,
	/// Most object ids a listing walk collects, whatever the page count.
	pub(crate) keys: usize,
}

impl Limits {
	/// An object is at most `max_message_size` (itself capped at 1 GiB) plus
	/// sidecars, so 1 GiB and a little headroom is the largest real body.
	pub(crate) const DEFAULT: Limits = Limits {
		connect: Duration::from_secs(10),
		read: Duration::from_secs(30),
		total: Duration::from_secs(900),
		object: (1 << 30) + (16 << 20),
		// S3 returns at most 1000 keys a page, a few hundred bytes each.
		listing: 16 << 20,
		// 10 000 pages of 1000 keys is ten million objects.
		pages: 10_000,
		keys: 10_000_000,
	};

	/// The HTTP client these limits describe. Redirects are not followed: the
	/// request is signed for one host, and a store that moves an object
	/// answers with the error the operator must fix, not a hop to chase.
	pub(crate) fn client(&self) -> reqwest::Client {
		reqwest::Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.connect_timeout(self.connect)
			.read_timeout(self.read)
			.timeout(self.total)
			.build()
			.expect("build the S3 HTTP client")
	}
}

/// Read a response body, refusing one over `cap` bytes. The declared length is
/// checked before any byte is read, and the bytes actually received are
/// counted as they arrive, so a peer that lies about its length or sends no
/// length at all is stopped at the same point.
pub(crate) async fn read_capped(
	mut response: reqwest::Response,
	cap: u64,
) -> Result<Vec<u8>, BlobError> {
	if let Some(declared) = response.content_length()
		&& declared > cap
	{
		return Err(over_limit(cap));
	}
	let mut body = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|error| BlobError::Remote(error.to_string()))?
	{
		if body.len() as u64 + chunk.len() as u64 > cap {
			return Err(over_limit(cap));
		}
		body.extend_from_slice(&chunk);
	}
	Ok(body)
}

fn over_limit(cap: u64) -> BlobError {
	BlobError::Remote(format!("the response body is over the {cap} byte limit"))
}
