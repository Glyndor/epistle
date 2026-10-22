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
//! A client that sends one of these fields twice keeps the first copy: RFC
//! 2369 lets the field appear more than once and does not say which one a
//! receiver should act on.

use std::collections::BTreeMap;

use crate::compose;
use crate::dmarc::author::{AuthorDomain, author_domain};
use crate::evidence::MailClass;
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
pub fn apply(
	message: &mut AcceptedMessage,
	class: MailClass,
	policy: &Policy,
	directory: Option<&crate::smtp::directory::Directory>,
) {
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
	// first.
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
		&& let Some(uri) = unsubscribe_uri(&sender)
	{
		strip_headers(&mut message.data, &["list-unsubscribe-post"]);
		push(
			&mut lines,
			"List-Unsubscribe",
			compose::structured("List-Unsubscribe", &uri),
		);
	}
	prepend(&mut message.data, &lines);
}

/// The `mailto:` `List-Unsubscribe` for `sender`, percent-encoded per
/// RFC 6068 so a `?`, an `&` or a `%` in the address cannot read as a query
/// separator, and `None` for an empty reverse path, which names nobody to
/// write to.
fn unsubscribe_uri(sender: &str) -> Option<String> {
	if sender.is_empty() {
		return None;
	}
	Some(format!(
		"<mailto:{}?subject=unsubscribe>",
		percent_encoding::utf8_percent_encode(sender, MAILTO_TEXT)
	))
}

/// The characters RFC 6068 leaves alone in a `mailto` address: the unreserved
/// set and the delimiters an address spec may carry. Everything else, `%`
/// and `?` and `&` included, is percent-encoded.
const MAILTO_TEXT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~')
	.remove(b'!')
	.remove(b'$')
	.remove(b'\'')
	.remove(b'(')
	.remove(b')')
	.remove(b'*')
	.remove(b'+')
	.remove(b',')
	.remove(b';')
	.remove(b':')
	.remove(b'@')
	.remove(b'/');

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

/// Put `lines` at the top of the header block, shifting the message up
/// inside the same buffer when there is something to add.
fn prepend(data: &mut Vec<u8>, lines: &str) {
	if lines.is_empty() {
		return;
	}
	let len = data.len();
	data.reserve_exact(lines.len());
	data.resize(len + lines.len(), 0);
	data.copy_within(..len, lines.len());
	data[..lines.len()].copy_from_slice(lines.as_bytes());
}

#[cfg(test)]
#[path = "identification_tests.rs"]
mod tests;
