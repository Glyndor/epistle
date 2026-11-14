//! A session signed in as an account that has since been disabled, or whose
//! credentials were reset, ends with an untagged `BYE` instead of running its
//! next command or pushing the next change it polled for.

use super::*;

/// What a session gets when its account was withdrawn, before the close.
const WITHDRAWN: &[u8] = b"* BYE account no longer available\r\n";

impl Server {
	/// When `session` is signed in as an account the directory no longer lets
	/// act ([`crate::smtp::directory::Directory::account_is_live`]), tell the
	/// client and return `true`: the connection ends here. Read from the live
	/// handle, not the session's own directory, which is the one of the
	/// moment the connection was accepted.
	pub(super) async fn end_if_withdrawn<S>(
		&self,
		stream: &mut S,
		clock: &SessionClock,
		session: &Session,
	) -> bool
	where
		S: AsyncWrite + Unpin + ?Sized,
	{
		let Some(account) = session.signed_in_account() else {
			return false;
		};
		if self.directory.account_is_live(account) {
			return false;
		}
		tracing::info!("closing an IMAP session whose account was disabled or reset");
		let _ = response_writer::write_response(stream, WITHDRAWN, clock, true).await;
		true
	}
}
