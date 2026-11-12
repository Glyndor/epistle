//! Storing a message: the message file and its envelope written atomically.

use std::collections::BTreeMap;
use std::fs;

use uuid::Uuid;

use super::*;

impl FsSpool {
	/// Persist one message crash-safely and return its spool id.
	///
	/// Both files are first written and fsynced under `tmp/`, then renamed
	/// into `new/` , envelope last, so a visible envelope guarantees a
	/// complete message file next to it. The directory that holds the new
	/// names is synced after each rename, so a power cut cannot bring an
	/// entry back under its previous name. `account` is the local account
	/// that submitted the message (used by the delivery log); pass `None` for
	/// the SMTP relay hop that has none. The caller-supplied `extra` correlation
	/// map is the `extra` object the API path may attach to a submission;
	/// the delivery log and webhooks copy it onto every record they emit,
	/// but it is never written into the message itself.
	pub fn store(
		&self,
		message: &AcceptedMessage,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
	) -> std::io::Result<Uuid> {
		self.store_as(message, Uuid::now_v7(), account, extra)
	}

	/// [`FsSpool::store`] for an entry whose delivery events belong to the
	/// hosted domain `owner`, which the caller has established itself.
	pub fn store_owned(
		&self,
		message: &AcceptedMessage,
		owner: Option<&str>,
		extra: &BTreeMap<String, String>,
	) -> std::io::Result<Uuid> {
		self.store_with(
			message,
			Uuid::now_v7(),
			&StoreOptions {
				account: None,
				extra,
				owner,
				class: crate::evidence::MailClass::Personal,
				evidence: None,
				retain_days: 0,
			},
		)
	}

	/// [`FsSpool::store`] under an id the caller chose, so a submission can
	/// name its queue entry before it is routed. The id must be fresh (a
	/// UUID v7 minted for this message); it is returned unchanged.
	pub fn store_as(
		&self,
		message: &AcceptedMessage,
		id: Uuid,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
	) -> std::io::Result<Uuid> {
		self.store_with(
			message,
			id,
			&StoreOptions {
				account,
				extra,
				// By design no owner: `store` and `store_as` are for mail the
				// server or an operator tool writes with no tenant behind it
				// (an alert e-mail). Whoever has a tenant's domain in hand
				// uses `store_owned` or `store_with`.
				owner: None,
				class: crate::evidence::MailClass::Personal,
				evidence: None,
				retain_days: 0,
			},
		)
	}

	/// Store `message` under `id` with `options`. Both files are written and
	/// synced under `tmp/` first. Then the evidence hook, when there is one,
	/// runs on the exact bytes queued: it writes the acceptance record, and
	/// only when it succeeds are the files renamed into `new/`, envelope last,
	/// where the worker can see them. The directory that holds the new names
	/// is synced after each rename, so the names survive a power cut. A hook
	/// failure removes the staged files and is returned, so nothing is queued
	/// that has no record. A crash between the hook and the renames leaves the
	/// staged files for [`FsSpool::leftovers`] to find at the next start.
	pub fn store_with(
		&self,
		message: &AcceptedMessage,
		id: Uuid,
		options: &StoreOptions<'_>,
	) -> std::io::Result<Uuid> {
		let account = options
			.account
			.filter(|value| !value.is_empty())
			.map(str::to_string);
		let envelope = Envelope {
			id,
			reverse_path: message.reverse_path.clone(),
			recipients: message.recipients.clone(),
			attempts: 0,
			next_attempt: 0,
			require_tls: message.require_tls,
			no_dsn: message.no_dsn.clone(),
			delay_warned: false,
			held: None,
			held_secs: 0,
			last_error: None,
			recipient_state: BTreeMap::new(),
			account,
			extra: options.extra.clone(),
			owner: options
				.owner
				.filter(|value| !value.is_empty())
				.map(str::to_ascii_lowercase),
			class: options.class,
			evidence: options.evidence.is_some(),
			retain_days: options.retain_days,
			outcomes_pending: Vec::new(),
			cancelling: None,
		};

		let tmp_message = self.entry_file(SpoolDir::Tmp, id, MessageExt::Eml)?;
		let tmp_envelope = self.entry_file(SpoolDir::Tmp, id, MessageExt::Json)?;
		let final_message = self.entry_file(SpoolDir::New, id, MessageExt::Eml)?;
		let final_envelope = self.entry_file(SpoolDir::New, id, MessageExt::Json)?;

		// Whatever path queued it, a message leaves with CRLF line ends, so
		// the bytes the evidence hook records are the ones sent. A NUL or a
		// bare CR is not repaired: the message is refused.
		if crate::util::header_block::has_unframed_byte(&message.data) {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"message holds a NUL or a bare carriage return",
			));
		}
		let data = crate::util::header_block::outbound_crlf(&message.data);
		write_sync(&tmp_message, &self.crypto.encode(&data)?)?;
		let envelope_bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		let envelope_sealed = self
			.crypto
			.encode_with_aad(&envelope_bytes, id.as_bytes())?;
		write_sync(&tmp_envelope, &envelope_sealed)?;
		if let Some(record) = options.evidence
			&& let Err(error) = record(&data)
		{
			let _ = fs::remove_file(&tmp_envelope);
			let _ = fs::remove_file(&tmp_message);
			return Err(error);
		}
		#[cfg(test)]
		if std::env::var_os("EPISTLE_TEST_ABORT_AFTER_EVIDENCE").is_some() {
			// The crash test: die between the evidence record and the queue.
			std::process::abort();
		}
		fs::rename(&tmp_message, &final_message)?;
		sync_dir_of(&final_message)?;
		fs::rename(&tmp_envelope, &final_envelope)?;
		sync_dir_of(&final_envelope)?;
		Ok(id)
	}
}
