//! `epistle domain add --send-only` and `epistle domain set --send-only|--full`:
//! the role of a hosted domain. It is the `send_only_domains` array of the
//! configuration file; a domain it does not list is `full`. The role decides
//! which records the domain needs in DNS (see [`crate::dns::skip::DomainRole`]).

use crate::cli::config_edit::ConfigDocument;
use crate::dns::skip::DomainRole;

/// Write `role` for `domain` into `document`. The stored form is the
/// lowercase name, as every entry of the configuration's domain lists is.
pub(super) fn apply(
	document: &mut ConfigDocument,
	domain: &str,
	role: DomainRole,
) -> Result<(), String> {
	let stored = domain.trim().to_ascii_lowercase();
	match role {
		DomainRole::SendOnly => document.add_string("send_only_domains", &stored),
		DomainRole::Full => document.remove_string("send_only_domains", &stored),
	}
}

/// Drop `domain` from `send_only_domains`: a removed domain leaves nothing
/// behind that names it.
pub(super) fn forget(document: &mut ConfigDocument, domain: &str) -> Result<(), String> {
	apply(document, domain, DomainRole::Full)
}
