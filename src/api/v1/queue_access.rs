//! Which queue entries a key reaches. One decision, for the list, the removal
//! and everything the queue-detail routes do, so the three cannot differ.
//!
//! An entry belongs to the hosted domain the server decided when it queued it
//! (`Envelope::owner`: the domain of the authenticated account that sent it,
//! of the local recipient that forwarded it, or of the delivery that produced
//! a report). The sender of the message writes its `MAIL FROM`, and so the
//! reverse-path: anyone can send mail from a tenant's domain, mail that is
//! the tenant's by name only, so it is never what decides. An entry with no
//! owner is reached by a key with no confinement and by nobody else.

use crate::api::Principal;
use crate::storage::Envelope;

/// Whether `principal` reaches `envelope`.
pub(super) fn reaches(principal: &Principal, envelope: &Envelope) -> bool {
	if principal.is_unrestricted() {
		return true;
	}
	if principal.bound_account().is_some() {
		return false;
	}
	envelope
		.owner
		.as_deref()
		.is_some_and(|domain| principal.admits_domain(domain))
}
