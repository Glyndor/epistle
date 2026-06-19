//! Sieve `vacation` autoresponse generation for local delivery (RFC 5230):
//! suppression rules and per-sender dedup, kept apart from the core delivery
//! flow. This is a child module of `delivery`, so it sees `LocalDelivery`'s
//! private fields.

use std::fs;

use crate::smtp::session::AcceptedMessage;

use super::LocalDelivery;

impl LocalDelivery {
	/// Build a vacation autoresponse, applying RFC 5230 suppression (null
	/// sender, automated or bulk/list mail) and per-sender-per-days dedup.
	/// `None` means no reply is sent.
	pub(super) fn vacation_reply(
		&self,
		account: &str,
		message: &AcceptedMessage,
		request: &crate::sieve::interp::VacationRequest,
	) -> Option<AcceptedMessage> {
		if message.reverse_path.is_empty() {
			return None;
		}
		let headers = String::from_utf8_lossy(&message.data);
		let header = |name: &str| header_field(&headers, name);
		// Don't autorespond to automated or bulk/list traffic.
		if header("auto-submitted").is_some_and(|value| !value.eq_ignore_ascii_case("no"))
			|| header("list-id").is_some()
			|| header("precedence").is_some_and(|value| {
				matches!(
					value.to_ascii_lowercase().as_str(),
					"bulk" | "list" | "junk"
				)
			}) {
			return None;
		}
		if !self.vacation_should_reply(account, &message.reverse_path, request.days) {
			return None;
		}
		let user_address = message
			.recipients
			.first()
			.map(String::as_str)
			.unwrap_or(account);
		let vacation = crate::sieve::vacation::Vacation {
			reason: &request.reason,
			subject: request.subject.as_deref(),
			from: request.from.as_deref(),
			user_address,
		};
		Some(crate::sieve::vacation::build_response(
			&vacation,
			&message.reverse_path,
			header("subject").as_deref(),
			header("message-id").as_deref(),
			std::time::SystemTime::now(),
		))
	}

	/// Whether a vacation reply to `sender` is due (none sent within `days`),
	/// recording this send. A per-account `.vacation/<hash>` marker file's
	/// modification time tracks the last reply.
	fn vacation_should_reply(&self, account: &str, sender: &str, days: u64) -> bool {
		let digest = ring::digest::digest(
			&ring::digest::SHA256,
			sender.to_ascii_lowercase().as_bytes(),
		);
		let name: String = digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
			use std::fmt::Write;
			let _ = write!(acc, "{byte:02x}");
			acc
		});
		let dir = self.accounts_root.join(account).join(".vacation");
		let marker = dir.join(name);
		if let Ok(meta) = fs::metadata(&marker)
			&& let Ok(modified) = meta.modified()
			&& modified
				.elapsed()
				.map(|age| age.as_secs() < days.saturating_mul(86_400))
				.unwrap_or(false)
		{
			return false;
		}
		let _ = fs::create_dir_all(&dir);
		let _ = fs::write(&marker, b"");
		true
	}
}

/// The first value of header `name` from a raw message's header block (the
/// folded value is returned trimmed; only the header section is scanned).
fn header_field(message: &str, name: &str) -> Option<String> {
	let header_block = message.split("\r\n\r\n").next().unwrap_or(message);
	for line in header_block.split("\r\n") {
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			return Some(value.trim().to_string());
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::directory_store::DirectoryHandle;
	use crate::sieve::interp::VacationRequest;

	fn delivery(dir: &std::path::Path) -> LocalDelivery {
		let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
		LocalDelivery::new(dir, directory).expect("delivery")
	}

	fn request() -> VacationRequest {
		VacationRequest {
			reason: "Away".to_string(),
			subject: None,
			from: None,
			days: 7,
		}
	}

	fn message(reverse_path: &str, headers: &str) -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: reverse_path.to_string(),
			recipients: vec!["alice@example.org".to_string()],
			data: format!("{headers}\r\n\r\nbody\r\n").into_bytes(),
			require_tls: false,
			mailbox: None,
			no_dsn: Vec::new(),
		}
	}

	#[test]
	fn suppresses_replies_per_rfc5230() {
		let dir = tempfile::tempdir().expect("tempdir");
		let d = delivery(dir.path());
		// Null sender: never autorespond.
		assert!(
			d.vacation_reply("alice", &message("", "Subject: x"), &request())
				.is_none()
		);
		// Automated mail.
		assert!(
			d.vacation_reply(
				"alice",
				&message("bob@example.net", "Auto-Submitted: auto-generated"),
				&request()
			)
			.is_none()
		);
		// Mailing-list mail.
		assert!(
			d.vacation_reply(
				"alice",
				&message("bob@example.net", "List-Id: <list.example.net>"),
				&request()
			)
			.is_none()
		);
		// Bulk precedence.
		assert!(
			d.vacation_reply(
				"alice",
				&message("bob@example.net", "Precedence: bulk"),
				&request()
			)
			.is_none()
		);
	}

	#[test]
	fn replies_once_then_dedups() {
		let dir = tempfile::tempdir().expect("tempdir");
		let d = delivery(dir.path());
		let msg = message("bob@example.net", "Subject: hi");
		// First reply is sent; an immediate second is suppressed by dedup.
		assert!(d.vacation_reply("alice", &msg, &request()).is_some());
		assert!(d.vacation_reply("alice", &msg, &request()).is_none());
	}
}
