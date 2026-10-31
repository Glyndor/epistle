//! The copy of a submitted message kept in the account's `Sent` folder.
//!
//! Split out of `run.rs` to keep the connection loop under the code-line
//! limit.

use super::Server;

impl Server {
	/// Whether a copy of the message this session is about to submit
	/// should be stored into the account's `Sent` folder. The
	/// precedence: the app password
	/// that authenticated the session overrides the account-wide
	/// setting when it carries an explicit value, otherwise the
	/// account-wide setting decides (default "on" when absent).
	pub(super) fn save_sent_enabled_for(&self, session: &crate::smtp::session::Session) -> bool {
		let Some(account) = session.authenticated() else {
			return false;
		};
		let directory = self.directory.current();
		// App password override first: an explicit `Some(false)` here
		// disables the save even if the account has it on.
		if let Some(label) = session.auth_app_password_label()
			&& let Some(value) = directory.app_password_save_sent(account, Some(label))
		{
			return value;
		}
		directory.save_sent_for(account).unwrap_or(true)
	}

	/// Store one copy of `data` into the account's `Sent` folder. The
	/// copy carries the `\Seen` flag and never includes a `Bcc:`
	/// header (the SMTP path strips Bcc before this is called). A
	/// quota-exhausted mailbox or any other filesystem error is
	/// logged and ignored: the message the client sent must still
	/// leave the server. The duplicate-guard call uses the
	/// `Message-ID:` the server stamped on the message when the
	/// client omitted one.
	pub(super) fn save_sent_copy(
		&self,
		session: &crate::smtp::session::Session,
		account: &str,
		data: &[u8],
	) {
		let Some(data_dir) = self.data_dir.as_ref() else {
			tracing::warn!(
				account = %crate::log_id::account(account),
				"save_sent: no data directory on this listener; skipping copy"
			);
			return;
		};
		let message_id = match crate::storage::save_sent::first_message_id(data) {
			Some(id) => id,
			None => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					"save_sent: message has no Message-ID after stamping; skipping copy"
				);
				return;
			}
		};
		// Reverse dedup: if the client appended first, a message with
		// this Message-ID already lives in Sent; the guard does not
		// know about it yet, but the on-disk scan does. Skip the save
		// so we do not produce a duplicate copy. The IMAP APPEND
		// fast path uses the same guard and skips its own copy when
		// the guard says the server already saved.
		if let Ok(Some(_existing)) =
			crate::storage::save_sent::lookup_sent_uid(data_dir, account, &message_id)
		{
			tracing::debug!(
				account = %crate::log_id::account(account),
				"save_sent: Message-ID already in Sent; skipping server-side copy"
			);
			return;
		}
		let crypto = self
			.crypto
			.as_deref()
			.cloned()
			.unwrap_or_else(crate::storage::MessageCrypto::disabled);
		let quota = self
			.quota
			.as_ref()
			.and_then(|quota| quota.limit(&self.directory.current(), account));
		match crate::storage::save_sent::store_copy(
			data_dir,
			account,
			data,
			&message_id,
			&crypto,
			quota,
		) {
			Ok(_uid) => {
				tracing::debug!(
					account = %crate::log_id::account(account),
					"save_sent: stored a copy in Sent"
				);
			}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"save_sent: could not store the copy; the message is still sent"
				);
			}
		}
		// The session is unused now (the message ID was already extracted)
		// but keep the parameter so the call site documents who owns
		// the audit log line.
		let _ = session;
	}
}

impl Server {
	/// Authenticated submission: stamp Message-ID and Date when the client
	/// omitted them. The domain is the reverse-path's own (the authenticated
	/// account's domain), with the server hostname as a last resort. It runs
	/// before the Received block is added so the trace header stays the
	/// outermost line, and it works inside the body's own buffer.
	pub(super) fn stamp_submission(
		message: &mut crate::smtp::session::AcceptedMessage,
		hostname: &str,
	) {
		let stamp_domain = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, d)| d.to_ascii_lowercase())
			.unwrap_or_else(|| hostname.to_ascii_lowercase());
		crate::smtp::trace::ensure_submission_headers_in_place(
			&mut message.data,
			&stamp_domain,
			std::time::SystemTime::now(),
		);
		// The MSA drops Bcc: those recipients are on the envelope.
		crate::smtp::trace::strip_bcc_in_place(&mut message.data);
		// The trace header is this hop's, written just above; a client may
		// not write one of its own.
		crate::smtp::trace::strip_headers_in_place(&mut message.data, &["received"]);
	}
}
