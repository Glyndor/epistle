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
//! Nothing here overwrites a field the client already wrote except the
//! list block of a list address, which is the same block local delivery
//! prepends.

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
			bulk_recipients: 1,
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

/// Write the headers `policy` asks for onto `message`, in the order
/// [`Policy`] documents: the vendor marker, then `Organization`, then
/// `Feedback-ID`, then the list block, then the bulk unsubscribe.
///
/// A field the client already wrote is left alone, except `Organization`,
/// which the domain's configured value replaces, and the list block of a
/// list address, which is the same block local delivery prepends.
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
	message.data = crate::smtp::trace::strip_headers_with_prefix(&client, "X-Epistle");
	strip_headers(&mut message.data, &["authentication-results"]);
	let mut lines = String::new();
	if policy.x_epistle {
		push(
			&mut lines,
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
		push(&mut lines, compose::structured("Organization", name));
	}
	if policy.feedback_id && !carries(&message.data, "feedback-id") {
		// The class and the domain, never the local part: the field exists
		// to tie a feedback loop to the sender, not to name the account.
		push(
			&mut lines,
			compose::structured("Feedback-ID", &format!("epistle:{class}:{domain}")),
		);
	}
	if policy.list_id
		&& let Some(directory) = directory
		&& let Some(block) = directory.list_headers(&sender)
	{
		strip_headers(
			&mut message.data,
			&["list-id", "list-post", "list-unsubscribe"],
		);
		lines.push_str(&block);
	}
	if policy.bulk_unsubscribe
		&& bulk(class, message.recipients.len(), policy.bulk_recipients)
		&& !carries(&message.data, "list-unsubscribe")
	{
		push(
			&mut lines,
			compose::structured(
				"List-Unsubscribe",
				&format!("<mailto:{sender}?subject=unsubscribe>"),
			),
		);
	}
	prepend(&mut message.data, &lines);
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

fn push(lines: &mut String, header: Result<String, compose::ComposeError>) {
	if let Ok(header) = header {
		lines.push_str(&header);
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
