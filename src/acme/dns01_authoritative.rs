//! DNS-01 propagation check against the zone's authoritative servers.
//!
//! A provider API accepting a record says nothing about when the zone's
//! name servers serve it, and the CA queries those servers (through its own
//! resolvers, which may hit any of them). Asking a recursive resolver would
//! be worse: it caches the NXDOMAIN from the first probe. So the check finds
//! the zone's NS set, resolves each server, and asks every address directly
//! with recursion off and no cache. The value is visible only when all of
//! them answer with it.
//!
//! The nameservers are asked through [`crate::dns::authoritative`], which
//! every caller that needs to know what a zone serves shares.
//!
//! This is network I/O glue, excluded from the no-network test suite; the
//! waiting and cleanup logic that uses it is tested with a fake.

use std::pin::Pin;

use super::challenge::TxtVisibility;
use crate::dns::authoritative::{AuthorityLookup, SystemAuthority};

/// Checks TXT visibility on the authoritative servers, finding them through
/// the host's resolver.
pub struct AuthoritativeTxt {
	authority: SystemAuthority,
}

impl AuthoritativeTxt {
	/// Build on the system resolver (the same TCP-only configuration the rest
	/// of the server uses).
	pub fn from_system() -> std::io::Result<Self> {
		Ok(AuthoritativeTxt {
			authority: SystemAuthority::from_system()?,
		})
	}
}

impl TxtVisibility for AuthoritativeTxt {
	fn visible<'a>(
		&'a self,
		name: &'a str,
		value: &'a str,
	) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async move {
			match self.authority.txt(name).await {
				Some(answer) => answer.all_serve(|served| served == value),
				None => false,
			}
		})
	}
}
