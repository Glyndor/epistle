//! What a directory server we do not control may make this process spend.
//!
//! The server is a remote peer: it can accept a connection and never answer a
//! bind, or answer a search with more entries than any real directory holds.
//! Both are bounded here, so a hostile or broken server costs one failed call
//! (which fails closed, like every other LDAP error) instead of a thread that
//! never returns or memory that grows with what the peer chooses to send.

use std::time::Duration;

use ldap3::{Ldap, Scope, SearchEntry};

/// A budget for one LDAP call: the whole of it, connect to unbind.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
	/// Wall-clock time for the call, covering connect, bind and search.
	pub(crate) timeout: Duration,
	/// Most entries a search may return before it is refused.
	pub(crate) entries: usize,
}

impl Limits {
	/// A login waits on this: long enough for a slow server, short enough
	/// that one silent server cannot hold every later login behind it.
	pub(crate) const AUTH: Limits = Limits {
		timeout: Duration::from_secs(30),
		entries: MAX_ENTRIES,
	};

	/// The periodic whole-directory load runs off the request path, so it may
	/// take longer.
	pub(crate) const LOAD: Limits = Limits {
		timeout: Duration::from_secs(300),
		entries: MAX_ENTRIES,
	};
}

/// Entries a search may return. A mail directory with more accounts than this
/// is not one this backend loads into memory whole.
const MAX_ENTRIES: usize = 100_000;

/// Run `work` for at most `limit`, mapping a lapse to `LdapError::Timeout`.
pub(crate) async fn within<T>(
	limit: Duration,
	work: impl std::future::Future<Output = ldap3::result::Result<T>>,
) -> ldap3::result::Result<T> {
	tokio::time::timeout(limit, work).await?
}

/// Search `base` and collect at most `cap` entries. A server that sends one
/// more is refused rather than read to the end, so the memory held is set by
/// the cap, not by the peer. A referral result is an error, as before.
pub(crate) async fn capped_search(
	conn: &mut Ldap,
	base: &str,
	filter: &str,
	attrs: Vec<&str>,
	cap: usize,
) -> ldap3::result::Result<Vec<SearchEntry>> {
	let mut stream = conn
		.streaming_search(base, Scope::Subtree, filter, attrs)
		.await?;
	let mut entries = Vec::new();
	while let Some(entry) = stream.next().await? {
		if entries.len() >= cap {
			return Err(ldap3::LdapError::Io {
				source: std::io::Error::other(format!(
					"the directory returned more than {cap} entries"
				)),
			});
		}
		entries.push(SearchEntry::construct(entry));
	}
	stream.finish().await.success()?;
	Ok(entries)
}
