//! Reading a remote server's SMTP reply: its basic code (RFC 5321 §4.2), its
//! enhanced status code (RFC 3463), and what a failure means for the
//! recipient.
//!
//! The enhanced status decides when it is present, because it says what the
//! basic code cannot: a 552 can be a full mailbox or a message too big, a 550
//! a missing mailbox or a spam rejection. Without one, the basic code
//! decides, conservatively: only replies that are about the address itself
//! (551, 553) count as a bad address.

/// What a delivery failure was about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
	/// The address does not exist or cannot receive mail (X.1.x).
	InvalidAddress,
	/// The mailbox is full (X.2.2).
	MailboxFull,
	/// Refused by policy: authentication, reputation, spam (X.7.x). This
	/// is about the sender, not the address.
	PolicyRejected,
	/// The message is larger than the remote accepts (X.3.4, X.2.3).
	TooBig,
	/// Anything else, including local errors with no reply at all.
	Other,
}

impl FailureClass {
	/// The stable name used in logs and webhook events.
	pub fn label(self) -> &'static str {
		match self {
			FailureClass::InvalidAddress => "invalid_address",
			FailureClass::MailboxFull => "mailbox_full",
			FailureClass::PolicyRejected => "policy_rejected",
			FailureClass::TooBig => "too_big",
			FailureClass::Other => "other",
		}
	}
}

/// What a failure means: its class, whether retrying is pointless, and
/// whether the address belongs on the suppression list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
	/// What the failure was about.
	pub class: FailureClass,
	/// The message will not get through to this recipient by retrying.
	pub permanent: bool,
	/// The address itself is bad: future mail to it should not be tried.
	pub suppress: bool,
}

/// An enhanced status code `class.subject.detail` (RFC 3463 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enhanced {
	/// 2, 4 or 5.
	pub class: u16,
	/// The subject (1 address, 2 mailbox, 3 mail system, 7 policy, ...).
	pub subject: u16,
	/// The detail within the subject.
	pub detail: u16,
}

impl std::fmt::Display for Enhanced {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
	}
}

/// Parse `token` as an enhanced status code.
pub fn parse_enhanced(token: &str) -> Option<Enhanced> {
	let mut parts = token.split('.');
	let mut next = || -> Option<u16> {
		let part = parts.next()?;
		if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		part.parse().ok()
	};
	let enhanced = Enhanced {
		class: next()?,
		subject: next()?,
		detail: next()?,
	};
	(parts.next().is_none() && matches!(enhanced.class, 2 | 4 | 5)).then_some(enhanced)
}

/// The enhanced status at the start of a reply's text, when its class agrees
/// with the basic `code`. One that contradicts the code is ignored, as
/// RFC 3463 §2 asks.
fn enhanced_for(code: u16, text: &str) -> Option<Enhanced> {
	let enhanced = parse_enhanced(text.split_whitespace().next()?)?;
	(enhanced.class == code / 100).then_some(enhanced)
}

/// A raw reply (one or more `code[-| ]text` lines) as one line:
/// `code [enhanced] text text ...`, with the enhanced status given once.
pub fn normalize(code: u16, raw: &str) -> String {
	let mut enhanced = None;
	let mut words: Vec<&str> = Vec::new();
	for line in raw.split("\r\n").filter(|line| !line.is_empty()) {
		let text = line.get(4..).unwrap_or_default();
		let mut tokens = text.split_whitespace().peekable();
		if let Some(found) = tokens.peek().and_then(|first| enhanced_for(code, first)) {
			tokens.next();
			enhanced.get_or_insert(found);
		}
		words.extend(tokens);
	}
	let mut line = code.to_string();
	if let Some(enhanced) = enhanced {
		line.push_str(&format!(" {enhanced}"));
	}
	for word in words {
		line.push(' ');
		line.push_str(word);
	}
	line
}

/// Classify a failure from its basic reply code and its text.
pub fn classify(code: u16, text: &str) -> Verdict {
	let verdict = |class, permanent, suppress| Verdict {
		class,
		permanent,
		suppress,
	};
	use FailureClass::*;
	let enhanced = enhanced_for(code, text).map(|e| (e.subject, e.detail));
	if code / 100 != 5 {
		// Transient by its basic code; the subject only names the cause.
		let class = match enhanced {
			Some((2, 2)) => MailboxFull,
			Some((7, _)) => PolicyRejected,
			Some((3, 4) | (2, 3)) => TooBig,
			_ => Other,
		};
		return verdict(class, false, false);
	}
	match enhanced {
		// X.1.7 and X.1.8 are about the sender's address, not the recipient's.
		Some((1, 7 | 8)) => verdict(Other, true, false),
		// Bad mailbox, bad domain, null MX (5.1.10).
		Some((1, _)) => verdict(InvalidAddress, true, true),
		// Mailbox full is persistent transient (RFC 3463 X.2.2): retried
		// until the message expires.
		Some((2, 2)) => verdict(MailboxFull, false, false),
		Some((3, 4) | (2, 3)) => verdict(TooBig, true, false),
		Some((7, _)) => verdict(PolicyRejected, true, false),
		// 5.2.1 mailbox disabled and every other 5.x.x: final for this
		// message, but no proof the address is bad.
		Some(_) => verdict(Other, true, false),
		// Exceeded storage allocation (RFC 5321 §4.5.3.1.10): retried.
		None if code == 552 => verdict(MailboxFull, false, false),
		None if matches!(code, 551 | 553) => verdict(InvalidAddress, true, true),
		None => verdict(Other, true, false),
	}
}

/// Classify a failure reason as the queue stores it: a normalized reply
/// (`550 5.1.1 ...`), or a local reason with no reply code, which is
/// [`FailureClass::Other`] and permanent only when `permanent` says so.
pub fn classify_reason(reason: &str, permanent: bool) -> Verdict {
	let code = reason
		.get(..3)
		.filter(|head| head.bytes().all(|b| b.is_ascii_digit()))
		.and_then(|head| head.parse::<u16>().ok())
		.filter(|code| (400..600).contains(code));
	match code {
		Some(code) => classify(code, reason.get(4..).unwrap_or_default()),
		None => Verdict {
			class: FailureClass::Other,
			permanent,
			suppress: false,
		},
	}
}

#[cfg(test)]
#[path = "reply_tests.rs"]
mod tests;
