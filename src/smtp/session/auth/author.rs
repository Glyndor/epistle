//! The send-as rule for the From and Sender headers of an authenticated
//! submission.
//!
//! MAIL FROM is checked when it arrives, but receivers judge the message
//! by its From header: that is the field DMARC aligns and the one the
//! DKIM signer signs under our domain. So an authenticated submission
//! must carry exactly one From field naming exactly one address, and the
//! account must own it (RFC 5322 section 3.6 allows a single From field;
//! a From with several authors would need a Sender, which no client of
//! this server sends).
//!
//! A `Sender` field is optional. When a submission carries one, the account
//! must own every address in it, the rule `POST /api/v1/send` and JMAP
//! `EmailSubmission/set` apply.

use crate::dmarc::author::{Author, author};
use crate::smtp::directory::sender_field::owned_sender_addresses;
use crate::smtp::identification::reject_ambiguous_headers;
use crate::smtp::session::{Address, Reply, Session};

/// `None` when `data` may be sent by the authenticated account, else the
/// refusal. Unauthenticated sessions are not submissions and pass.
pub(in crate::smtp::session) fn check(session: &Session, data: &[u8]) -> Option<Reply> {
	let account = session.authenticated.as_deref()?;
	if let Err(refusal) = reject_ambiguous_headers(data) {
		return Some(refusal.smtp_reply());
	}
	let owned = match author(data) {
		Author::Addresses(addresses) => match addresses.as_slice() {
			[address] => Address::parse(address)
				.is_ok_and(|address| session.directory.owns_address(account, &address)),
			_ => false,
		},
		Author::Missing | Author::MultipleFields => false,
	};
	if !owned {
		return Some(Reply::single(
			550,
			"5.7.1 From header not owned by the authenticated account",
		));
	}
	owned_sender_addresses(data, |address| {
		session.directory.owns_address(account, address)
	})
	.is_err()
	.then(|| {
		Reply::single(
			550,
			"5.7.1 Sender header not owned by the authenticated account",
		)
	})
}
