//! The identification and reputation headers the server writes on a
//! submission, and the policy that says which of them are on.
//!
//! Every submission path (SMTP after AUTH, `POST /api/v1/send`, JMAP
//! `EmailSubmission/set`) goes through
//! [`crate::evidence::submission::prepare`], which calls [`apply`] with the
//! class the server granted. One function, three paths: the same message
//! carries the same fields whichever way it was submitted, and every field
//! it writes lands before the message is DKIM-signed, so a receiver can
//! tell the server's fields from a client's.
//!
//! Nothing here overwrites a field the client already wrote, with two
//! exceptions the [`Policy`] documents: `Organization`, when the domain has
//! a configured value, and the `List-Id`/`List-Post` pair of a list
//! address, which is the same block local delivery prepends. A
//! `List-Unsubscribe` the client chose, one-click included, is always kept.
//! A client that sends one of these fields twice keeps the first copy: one
//! field may carry several URLs, which is one claim about how to leave, while
//! a second field of the same name is a second claim about the same header and
//! nothing in RFC 2369 or RFC 8058 says which one a receiver acts on.

use std::collections::BTreeMap;

use crate::compose;
use crate::dmarc::author::{AuthorDomain, author_domain};
use crate::evidence::MailClass;
use crate::evidence::marketing::MarketingRefusal;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::trace::header_values;

/// The value of the vendor marker, with no version riding in it: the field
/// says this message left an epistle server, nothing about which one.
pub const X_EPISTLE_VALUE: &str = "1";

/// The `Auto-Submitted` value for mail the server generates itself.
pub const SYSTEM_AUTO_SUBMITTED: &str = "auto-generated";

/// Recipients above which a `transactional` submission counts as bulk by
/// default: twenty-one. Two recipients is an ordinary notice to two people,
/// not bulk mail, and an unsubscribe address on it would be the sender's
/// mailbox offered to a recipient who never asked to leave anything.
pub const DEFAULT_BULK_RECIPIENTS: usize = 20;

/// One switch per header, read from the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
	/// Write a `Feedback-ID` when the submission has none.
	pub feedback_id: bool,
	/// Give a bulk `transactional` submission a `mailto` `List-Unsubscribe`.
	pub bulk_unsubscribe: bool,
	/// Recipients above which a `transactional` submission counts as bulk.
	pub bulk_recipients: usize,
	/// Write the `List-Id` of the list the envelope sender speaks for.
	pub list_id: bool,
	/// Write `Auto-Submitted: auto-generated` on server-generated mail.
	pub system_auto_submitted: bool,
	/// Write `X-Epistle: 1`.
	pub x_epistle: bool,
	/// Write `Organization` for a domain that has one configured.
	pub organization: bool,
	/// The `Organization` value of each domain.
	pub domain_organization: BTreeMap<String, String>,
}

impl Default for Policy {
	/// Every header on except the vendor marker, which is off.
	fn default() -> Self {
		Self {
			feedback_id: true,
			bulk_unsubscribe: true,
			bulk_recipients: DEFAULT_BULK_RECIPIENTS,
			list_id: true,
			system_auto_submitted: true,
			x_epistle: false,
			organization: true,
			domain_organization: BTreeMap::new(),
		}
	}
}

impl Policy {
	/// The policy the configuration asks for.
	pub fn from_config(config: &crate::config::Config) -> Self {
		Self {
			feedback_id: config.default_feedback_id,
			bulk_unsubscribe: config.default_list_unsubscribe,
			bulk_recipients: config.bulk_recipients,
			list_id: config.default_list_id,
			system_auto_submitted: config.system_auto_submitted,
			x_epistle: config.x_epistle_header,
			organization: config.organization_header,
			domain_organization: config
				.domain_organization
				.iter()
				.map(|(domain, name)| (domain.to_ascii_lowercase(), name.clone()))
				.collect(),
		}
	}
}

/// The fields of a submission that say who sent it and how to leave it. A
/// client may send them, one copy of each: the server then decides each in
/// its own way, replacing the client's copy, adding one where there is none,
/// or leaving the one it sent.
const IDENTIFICATION_FIELDS: &[&str] = &[
	"feedback-id",
	"list-id",
	"list-post",
	"list-unsubscribe",
	"list-unsubscribe-post",
	"organization",
];

/// Write the headers `policy` asks for onto `message`, in the order
/// [`Policy`] documents: the vendor marker, then `Organization`, then
/// `Feedback-ID`, then the list block, then the bulk unsubscribe.
///
/// A field the client already wrote is left alone, with the two exceptions
/// the module says: `Organization`, which the domain's configured value
/// replaces, and the `List-Id`/`List-Post` of a list address, which is the
/// same block local delivery prepends. Exactly one of each field above ever
/// goes out: whichever came first, the client's, the list's or the bulk one,
/// wins and the others are not written.
///
/// A header block with an ambiguous field name or framing is refused before
/// any header changes.
pub fn apply(
	message: &mut AcceptedMessage,
	class: MailClass,
	policy: &Policy,
	directory: Option<&crate::smtp::directory::Directory>,
) -> Result<(), MarketingRefusal> {
	reject_ambiguous_headers(&message.data)?;
	let sender = message.reverse_path.clone();
	let domain = sending_domain(&message.data, &sender);
	// Nothing a client wrote in our namespace, or about checks this hop
	// never made, survives a submission: `X-Epistle-*` is ours to write and
	// a submission carries no authentication results of its own. The
	// trace header is a different case, handled where it is written (the
	// SMTP session) or where the client's bytes are taken (a JMAP draft),
	// because this step sees the server's own trace header on the SMTP
	// path already.
	let client = std::mem::take(&mut message.data);
	message.data = crate::smtp::trace::strip_headers_with_namespace(&client, "X-Epistle");
	strip_headers(&mut message.data, &["authentication-results"]);
	// Two of one field are two claims about the same thing and no reason to
	// read both, so what the client wrote twice is reduced to what it wrote
	// first, whichever way it spelled the name.
	crate::smtp::trace::keep_first_of_each_in_place(&mut message.data, IDENTIFICATION_FIELDS);
	let mut lines = String::new();
	if policy.x_epistle {
		push(
			&mut lines,
			"X-Epistle",
			compose::unstructured("X-Epistle", X_EPISTLE_VALUE),
		);
	}
	// The operator's value for the domain is the only one that says anything
	// about this server, so it replaces whatever the client wrote. With no
	// value configured the client's own claim is left alone: the server has
	// no opinion to overrule it with.
	if policy.organization
		&& let Some(name) = policy.domain_organization.get(&domain)
	{
		strip_headers(&mut message.data, &["organization"]);
		push(
			&mut lines,
			"Organization",
			compose::structured("Organization", name),
		);
	}
	// An empty reverse path says nothing about who to write back to, so the
	// field is left out rather than written with an empty domain after the
	// class. A domain outside ASCII is refused by the composer and said once
	// an hour, never dropped without a word.
	if policy.feedback_id && !sender.is_empty() && !carries(&message.data, "feedback-id") {
		// The class and the domain, never the local part: the field exists
		// to tie a feedback loop to the sender, not to name the account.
		push(
			&mut lines,
			"Feedback-ID",
			compose::structured("Feedback-ID", &format!("epistle:{class}:{domain}")),
		);
	}
	// The list block claims the fields that say what the list is, and the
	// unsubscribe only when the client left none: a sender that already
	// published a one-click URL keeps it, and RFC 8058 wants it signed and
	// answered rather than replaced by an address nobody posts to.
	let mut unsubscribed = carries(&message.data, "list-unsubscribe");
	if policy.list_id
		&& let Some(directory) = directory
		&& let Some(identity) = directory.list_identity(&sender)
	{
		strip_headers(&mut message.data, &["list-id", "list-post"]);
		lines.push_str(&identity);
		if !unsubscribed && let Some(unsubscribe) = directory.list_unsubscribe(&sender) {
			lines.push_str(&unsubscribe);
			// RFC 8058 posts to an `https` URL, and the mailto the list
			// block just wrote is not one, so a post the client left
			// behind now names something the message does not carry.
			strip_headers(&mut message.data, &["list-unsubscribe-post"]);
			unsubscribed = true;
		}
	}
	if policy.bulk_unsubscribe
		&& !unsubscribed
		&& bulk(class, message.recipients.len(), policy.bulk_recipients)
		&& !sender.is_empty()
	{
		strip_headers(&mut message.data, &["list-unsubscribe-post"]);
		push(
			&mut lines,
			"List-Unsubscribe",
			compose::structured(
				"List-Unsubscribe",
				&crate::util::mailto::unsubscribe(&sender),
			),
		);
	}
	crate::smtp::trace::prepend_header_block(&mut message.data, &lines);
	Ok(())
}

/// Reject a header block whose lines are not the fields RFC 5322 sections 2.2
/// and 3.6.8 describe, and a block whose framing a server and a reader could
/// read differently. I compare identity field counts against mail-parser
/// too, because a field parser can consume the blank line before the body.
///
/// Every line of the block must be a field, whose name is one or more
/// printable US-ASCII characters other than a colon and with no white space
/// inside it, or a folded continuation of the field before it. White space
/// immediately before the colon stays accepted, under the obsolete syntax
/// readers still allow. A line that is neither, a name with a control byte in
/// it, a bare carriage return and mixed line endings are all refused, so the
/// fields the server reads and the fields a reader reads are the same ones.
pub fn reject_ambiguous_headers(data: &[u8]) -> Result<(), MarketingRefusal> {
	let mut has_field = false;
	let mut line_ending = None;
	let mut line_start = 0;
	let mut fields = (0, 0);
	while line_start < data.len() {
		let remaining = &data[line_start..];
		let Some(line_feed) = remaining.iter().position(|byte| *byte == b'\n') else {
			let line = &data[line_start..];
			if line.contains(&b'\r') {
				return Err(MarketingRefusal::AmbiguousHeaderFraming);
			}
			check_header_line(line, &mut has_field, &mut fields)?;
			break;
		};
		let raw_line = &remaining[..line_feed];
		let (line, ending) = match raw_line.split_last() {
			Some((b'\r', name)) => (name, LineEnding::Crlf),
			_ => (raw_line, LineEnding::Lf),
		};
		if line.contains(&b'\r') {
			return Err(MarketingRefusal::AmbiguousHeaderFraming);
		}
		if line_ending.is_some_and(|known| known != ending) {
			return Err(MarketingRefusal::AmbiguousHeaderFraming);
		}
		line_ending = Some(ending);
		if line.is_empty() {
			break;
		}
		check_header_line(line, &mut has_field, &mut fields)?;
		line_start += line_feed + 1;
	}
	// The reader below allocates per field, so the bound has to come first.
	if fields.0 > crate::smtp::trace::MAX_HEADER_FIELDS {
		return Err(MarketingRefusal::TooManyHeaderFields);
	}
	let from =
		crate::dmarc::author::from_fields(data).ok_or(MarketingRefusal::InvalidHeaderEncoding)?;
	// I parse headers once, with the dependency's normal field parsers, and
	// count both identities together without decoding MIME or the body. I
	// also compare the total, so removing a swallowed reserved field cannot
	// expose an identity from the body after this check.
	let mut reader = (0, 0, 0);
	if let Some(message) = mail_parser::MessageParser::default().parse_headers(data) {
		for header in message.headers() {
			reader.2 += 1;
			match header.name() {
				mail_parser::HeaderName::From => reader.0 += 1,
				mail_parser::HeaderName::Sender => reader.1 += 1,
				_ => {}
			}
		}
	}
	compare_header_readers(reader, (from.len(), fields.1, fields.0))
}

/// Compare (From, Sender, total) counts without depending on a particular
/// parser bug to exercise the refusal paths.
fn compare_header_readers(
	reader: (usize, usize, usize),
	author: (usize, usize, usize),
) -> Result<(), MarketingRefusal> {
	if reader != author {
		return Err(if (reader.0, reader.1) != (author.0, author.1) {
			MarketingRefusal::HeaderReaderMismatch
		} else {
			MarketingRefusal::HeaderReaderFramingMismatch
		});
	}
	Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineEnding {
	Crlf,
	Lf,
}

fn check_header_line(
	line: &[u8],
	has_field: &mut bool,
	fields: &mut (usize, usize),
) -> Result<(), MarketingRefusal> {
	if matches!(line.first(), Some(b' ' | b'\t')) {
		return if *has_field {
			Ok(())
		} else {
			Err(MarketingRefusal::MalformedHeaderLine)
		};
	}
	let Some(colon) = line.iter().position(|byte| *byte == b':') else {
		return Err(MarketingRefusal::MalformedHeaderLine);
	};
	let raw_name = &line[..colon];
	let name_end = raw_name
		.iter()
		.rposition(|byte| !matches!(byte, b' ' | b'\t'))
		.map_or(0, |index| index + 1);
	let name = &raw_name[..name_end];
	if name.is_empty() {
		return Err(MarketingRefusal::MalformedHeaderLine);
	}
	if !name.iter().all(|byte| is_field_name_byte(*byte)) {
		return Err(MarketingRefusal::AmbiguousHeaderName);
	}
	*has_field = true;
	fields.0 += 1;
	if name.eq_ignore_ascii_case(b"sender") {
		fields.1 += 1;
	}
	Ok(())
}

fn is_field_name_byte(byte: u8) -> bool {
	(33..=126).contains(&byte) && byte != b':'
}

/// Whether a submission counts as bulk for the `mailto` unsubscribe.
///
/// `transactional` only: marketing mail already has to carry a one-click
/// unsubscribe the sender controls, and personal mail is correspondence
/// between people, where an unsubscribe address would be a stranger's
/// mailbox offered to everyone.
fn bulk(class: MailClass, recipients: usize, threshold: usize) -> bool {
	class == MailClass::Transactional && recipients > threshold
}

/// The domain a submission is sent for: the one its single `From` names,
/// else the envelope sender's. Lowercased; empty when neither has one.
fn sending_domain(data: &[u8], sender: &str) -> String {
	let from = match author_domain(data) {
		AuthorDomain::One(domain) => Some(domain),
		AuthorDomain::Missing | AuthorDomain::Multiple => None,
	};
	from.or_else(|| {
		sender
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase())
	})
	.unwrap_or_default()
}

/// Whether the message already carries a field named `name`.
fn carries(data: &[u8], name: &str) -> bool {
	!header_values(data, name).is_empty()
}

/// Append a composed header, or say once an hour that it was left out. A
/// value the composer refuses is a message that goes without the field, and
/// an operator looking at a receiver's headers has to be able to find out
/// why, so the refusal is never swallowed.
fn push(lines: &mut String, name: &str, header: Result<String, compose::ComposeError>) {
	match header {
		Ok(header) => lines.push_str(&header),
		Err(error) => {
			if crate::util::warn_limited::allow(&format!("identification:{name}")) {
				tracing::warn!(%name, %error, "identification header left out of the message");
			}
		}
	}
}

fn strip_headers(data: &mut Vec<u8>, names: &[&str]) {
	crate::smtp::trace::strip_headers_in_place(data, names);
}

#[cfg(test)]
mod tests;
