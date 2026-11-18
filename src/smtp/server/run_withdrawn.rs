//! A session signed in as an account that has since been disabled, or whose
//! credentials were reset, ends instead of running its next command or
//! delivering the message it was sending. Split from `run.rs` to keep the
//! connection loop under the code-line limit.

use crate::smtp::reply::Reply;
use crate::smtp::session::Session;

use super::{Connection, Server, send};

impl Server {
	/// Whether `session` is signed in as an account the directory no longer
	/// lets act ([`crate::smtp::directory::Directory::account_is_live`]).
	/// Read from the live handle, not the session's snapshot, so a change
	/// published after the last command is seen.
	pub(super) fn account_withdrawn(&self, session: &Session) -> bool {
		session
			.authenticated()
			.is_some_and(|account| !self.directory.account_is_live(account))
	}
}

/// End a session whose account was withdrawn: the session goes first, so what
/// it held, a message body in flight included, is dropped even if the client
/// never reads the 421.
pub(super) async fn end_withdrawn(
	stream: &mut Box<dyn Connection>,
	session: Session,
) -> std::io::Result<()> {
	drop(session);
	tracing::info!("closing a session whose account was disabled or reset");
	send(stream, &withdrawn()).await
}

/// What a session gets when its account was withdrawn, before the close.
fn withdrawn() -> Reply {
	Reply::single(421, "4.7.0 account no longer available")
}
