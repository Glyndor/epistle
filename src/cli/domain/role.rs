//! `epistle domain add --send-only|--receive-only` and `epistle domain set
//! --send-only|--receive-only|--full`: the role of a hosted domain. It is the
//! `send_only_domains` and `receive_only_domains` arrays of the
//! configuration file; a domain neither lists is `full`, and a domain is in
//! at most one of them. The role decides which records the domain needs in
//! DNS and whether anybody may send as it (see
//! [`crate::dns::skip::DomainRole`]). A domain that neither sends nor
//! receives is switched off with `domain disable`, not with a role.

use crate::cli::config_edit::ConfigDocument;
use crate::dns::skip::DomainRole;

/// Write `role` for `domain` into `document`. The stored form is the
/// lowercase name, as every entry of the configuration's domain lists is.
/// Giving one role takes the domain out of the other list.
pub(super) fn apply(
	document: &mut ConfigDocument,
	domain: &str,
	role: DomainRole,
) -> Result<(), String> {
	let stored = domain.trim().to_ascii_lowercase();
	match role {
		DomainRole::SendOnly => {
			document.remove_string("receive_only_domains", &stored)?;
			document.add_string("send_only_domains", &stored)
		}
		DomainRole::ReceiveOnly => {
			document.remove_string("send_only_domains", &stored)?;
			document.add_string("receive_only_domains", &stored)
		}
		DomainRole::Full => {
			document.remove_string("send_only_domains", &stored)?;
			document.remove_string("receive_only_domains", &stored)
		}
		DomainRole::Disabled => Err(
			"a domain that neither sends nor receives is switched off with `domain disable`".into(),
		),
	}
}

/// Drop `domain` from the role lists: a removed domain leaves nothing
/// behind that names it.
pub(super) fn forget(document: &mut ConfigDocument, domain: &str) -> Result<(), String> {
	apply(document, domain, DomainRole::Full)
}
