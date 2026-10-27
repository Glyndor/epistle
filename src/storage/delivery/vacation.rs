//! Vacation autoresponses for local delivery: the Sieve `vacation` action
//! (RFC 5230) and the JMAP `VacationResponse` (RFC 8621 section 8). Both
//! go through one set of suppression rules (RFC 3834 section 2, RFC 5230
//! section 4) and one per-sender tracker, so the two can never answer one
//! message twice. This is a child module of `delivery`, so it sees
//! `LocalDelivery`'s private fields.

use crate::sieve::interp::VacationRequest;
use crate::sieve::vacation::{Original, Vacation, build_response};
use crate::smtp::session::AcceptedMessage;
use crate::storage::vacation_markers;
use crate::storage::vacation_store::{self, VacationSetting};

use super::LocalDelivery;

/// Period of the JMAP `VacationResponse`, which has no `:days` of its own:
/// RFC 5230's default, shared with the Sieve markers.
pub(super) const JMAP_VACATION_DAYS: u64 = 7;

/// Local parts of list robots and bounce senders (RFC 5230 section 4.6).
const ROBOTS: [&str; 3] = ["mailer-daemon", "listserv", "majordomo"];

/// RFC 2369 list headers: any one of them marks list mail.
const LIST_HEADERS: [&str; 7] = [
	"list-id",
	"list-help",
	"list-subscribe",
	"list-unsubscribe",
	"list-post",
	"list-owner",
	"list-archive",
];

impl LocalDelivery {
	/// The account's vacation reply to `message`, delivered as
	/// `delivered_to`. An enabled JMAP `VacationResponse` is the account's
	/// vacation: while it is enabled the Sieve `vacation` action is ignored,
	/// and outside its date window nothing is sent. Otherwise the Sieve
	/// action, if the script ran one, answers.
	pub(super) fn vacation_autoreply(
		&self,
		account: &str,
		delivered_to: &str,
		message: &AcceptedMessage,
		sieve: Option<&VacationRequest>,
	) -> Option<AcceptedMessage> {
		match self.jmap_vacation(account) {
			Some(setting) if setting.is_within_window(now_unix_secs()) => {
				self.jmap_vacation_reply(account, delivered_to, message, &setting)
			}
			Some(_) => None,
			None => self.vacation_reply(account, delivered_to, message, sieve?),
		}
	}

	/// The Sieve `vacation` reply. A `:from` the account does not own is
	/// ignored, or a script could send mail as anyone.
	pub(super) fn vacation_reply(
		&self,
		account: &str,
		delivered_to: &str,
		message: &AcceptedMessage,
		request: &VacationRequest,
	) -> Option<AcceptedMessage> {
		let from = request
			.from
			.as_deref()
			.filter(|from| self.owns(account, delivered_to, from));
		let vacation = Vacation {
			reason: &request.reason,
			subject: request.subject.as_deref(),
			from,
			user_address: delivered_to,
			html_body: None,
		};
		self.answer(account, delivered_to, message, &vacation, request.days)
	}

	/// The JMAP `VacationResponse` reply (RFC 8621 section 8).
	pub(super) fn jmap_vacation_reply(
		&self,
		account: &str,
		delivered_to: &str,
		message: &AcceptedMessage,
		setting: &VacationSetting,
	) -> Option<AcceptedMessage> {
		if !setting.is_enabled {
			return None;
		}
		let vacation = Vacation {
			reason: setting.text_body.as_deref().unwrap_or(""),
			subject: setting.subject.as_deref(),
			from: None,
			user_address: delivered_to,
			html_body: setting.html_body.as_deref(),
		};
		self.answer(
			account,
			delivered_to,
			message,
			&vacation,
			JMAP_VACATION_DAYS,
		)
	}

	/// The enabled JMAP setting for `account`. A read or parse error is "no
	/// JMAP vacation", so a damaged file cannot make the server answer.
	pub(super) fn jmap_vacation(&self, account: &str) -> Option<VacationSetting> {
		vacation_store::read(&self.data_dir, account)
			.ok()
			.filter(|setting| setting.is_enabled)
	}

	/// The reply, sent to the envelope reverse-path (RFC 3834 section 4)
	/// and never to a header address, unless a suppression rule applies or
	/// the sender already had one within `days`. The server must have
	/// verified the sender itself (`sender_verified`: SPF or DKIM on the
	/// inbound hop, or a login), and one of the account's addresses must
	/// be in To or Cc (RFC 5230 section 4.5): mail that reached the account
	/// through Bcc, a list or an alias is not answered.
	fn answer(
		&self,
		account: &str,
		delivered_to: &str,
		message: &AcceptedMessage,
		vacation: &Vacation,
		days: u64,
	) -> Option<AcceptedMessage> {
		let sender = message.reverse_path.as_str();
		if !message.sender_verified
			|| sender.is_empty()
			|| robot(sender)
			|| self.owns(account, delivered_to, sender)
		{
			return None;
		}
		let headers = String::from_utf8_lossy(header_block(&message.data));
		let header = |name: &str| crate::util::header::header_value(&headers, name);
		if automated(&header) || !self.addressed(account, delivered_to, &headers) {
			return None;
		}
		if !vacation_markers::claim(&self.data_dir, account, sender, days) {
			return None;
		}
		let (subject, message_id, references) = (
			header("subject"),
			header("message-id"),
			header("references"),
		);
		let original = Original {
			subject: subject.as_deref(),
			message_id: message_id.as_deref(),
			references: references.as_deref(),
		};
		build_response(vacation, sender, &original, std::time::SystemTime::now())
	}

	/// Whether one of the account's addresses, `delivered_to` included, is
	/// in the To or Cc of `headers`.
	fn addressed(&self, account: &str, delivered_to: &str, headers: &str) -> bool {
		let fields = to_and_cc(headers);
		let mut own = self.directory.current().addresses_for(account);
		own.push(delivered_to.to_string());
		own.iter()
			.any(|address| names(&fields, &address.to_ascii_lowercase()))
	}

	/// Whether `address` is one of the account's own: an answer to it would
	/// be the account writing to itself.
	fn owns(&self, account: &str, delivered_to: &str, address: &str) -> bool {
		address.eq_ignore_ascii_case(delivered_to)
			|| address.eq_ignore_ascii_case(account)
			|| self
				.directory
				.current()
				.addresses_for(account)
				.iter()
				.any(|own| own.eq_ignore_ascii_case(address))
	}
}

/// A bounce or list-robot sender.
fn robot(sender: &str) -> bool {
	let local = sender.rsplit_once('@').map_or(sender, |(local, _)| local);
	let local = local.to_ascii_lowercase();
	ROBOTS.contains(&local.as_str()) || local.starts_with("owner-") || local.ends_with("-request")
}

/// Automated or list mail (RFC 3834 section 2, RFC 5230 section 4.6):
/// `Auto-Submitted` other than `no`, an RFC 2369 list header, or
/// `Precedence: bulk`, `list` or `junk`.
fn automated(header: &dyn Fn(&str) -> Option<String>) -> bool {
	let auto_submitted = header("auto-submitted").is_some_and(|value| {
		let keyword = value.split(';').next().unwrap_or_default().trim();
		!keyword.eq_ignore_ascii_case("no")
	});
	let precedence = header("precedence").is_some_and(|value| {
		["bulk", "list", "junk"]
			.iter()
			.any(|kind| value.trim().eq_ignore_ascii_case(kind))
	});
	auto_submitted || precedence || LIST_HEADERS.iter().any(|name| header(name).is_some())
}

/// Every To and Cc value in `headers`, unfolded and lowercased, joined by
/// commas.
fn to_and_cc(headers: &str) -> String {
	let mut fields = String::new();
	let mut wanted = false;
	for line in headers.lines() {
		if line.starts_with([' ', '\t']) {
			if wanted {
				fields.push_str(line);
			}
			continue;
		}
		let (name, value) = line.split_once(':').unwrap_or((line, ""));
		wanted = ["to", "cc"]
			.iter()
			.any(|field| name.trim().eq_ignore_ascii_case(field));
		if wanted {
			fields.push(',');
			fields.push_str(value);
		}
	}
	fields.to_ascii_lowercase()
}

/// Whether `fields` holds `address` as a whole address: not as the tail of
/// a longer local part or the head of a longer domain.
fn names(fields: &str, address: &str) -> bool {
	let bytes = fields.as_bytes();
	fields.match_indices(address).any(|(at, _)| {
		let end = at + address.len();
		let before = at.checked_sub(1).map(|index| bytes[index]);
		let after = bytes.get(end).copied();
		!before.is_some_and(is_local_part_byte) && !after.is_some_and(is_domain_byte)
	})
}

/// A byte that can sit in an unquoted local part: RFC 5322 `atext`, plus the
/// dot that separates the atoms.
fn is_local_part_byte(byte: u8) -> bool {
	crate::util::validation::is_atext_byte(byte) || byte == b'.'
}

/// A byte that can sit in a domain name.
fn is_domain_byte(byte: u8) -> bool {
	byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.'
}

/// The header section of a raw message, up to its blank line.
fn header_block(data: &[u8]) -> &[u8] {
	let end = data
		.windows(4)
		.position(|window| window == b"\r\n\r\n")
		.unwrap_or(data.len());
	&data[..end]
}

/// The current Unix time in seconds; the clock the date window compares to.
fn now_unix_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
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
			data: format!("To: alice@example.org\r\n{headers}\r\n\r\nbody\r\n").into_bytes(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: true,
			no_dsn: Vec::new(),
		}
	}

	#[test]
	fn suppresses_replies_per_rfc5230() {
		let dir = tempfile::tempdir().expect("tempdir");
		let d = delivery(dir.path());
		// Null sender: never autorespond.
		assert!(
			d.vacation_reply(
				"alice",
				"alice@example.org",
				&message("", "Subject: x"),
				&request()
			)
			.is_none()
		);
		// Automated mail.
		assert!(
			d.vacation_reply(
				"alice",
				"alice@example.org",
				&message("bob@example.net", "Auto-Submitted: auto-generated"),
				&request()
			)
			.is_none()
		);
		// Mailing-list mail.
		assert!(
			d.vacation_reply(
				"alice",
				"alice@example.org",
				&message("bob@example.net", "List-Id: <list.example.net>"),
				&request()
			)
			.is_none()
		);
		// Bulk precedence.
		assert!(
			d.vacation_reply(
				"alice",
				"alice@example.org",
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
		assert!(
			d.vacation_reply("alice", "alice@example.org", &msg, &request())
				.is_some()
		);
		assert!(
			d.vacation_reply("alice", "alice@example.org", &msg, &request())
				.is_none()
		);
	}

	#[test]
	fn a_traversing_account_gets_no_marker() {
		let outer = tempfile::tempdir().expect("tempdir");
		let data = outer.path().join("data");
		std::fs::create_dir_all(&data).expect("data dir");
		let d = delivery(&data);
		assert!(!vacation_markers::claim(
			&d.data_dir,
			"../evil",
			"bob@example.net",
			7
		));
		let msg = message("bob@example.net", "Subject: hi");
		assert!(
			d.vacation_reply("../evil", "alice@example.org", &msg, &request())
				.is_none()
		);
		assert!(
			!data.join("evil").exists(),
			"nothing was written outside accounts/"
		);
		assert!(!data.join("accounts/../evil").exists());
	}
}

#[cfg(test)]
#[path = "vacation_jmap_tests.rs"]
mod jmap_tests;

#[cfg(test)]
#[path = "vacation_guard_tests.rs"]
mod guard_tests;
