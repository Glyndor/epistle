//! The zone that holds a record name, as the provider knows it.
//!
//! A record name is not a zone. `mail.example.org` is a name inside the
//! `example.org` zone, and a provider that names its zones (Cloudflare,
//! DNSimple, DigitalOcean, Google Cloud DNS, Namecheap, OVH) looks a zone
//! up by its exact name: handed the name, it answers "zone not found" and
//! the write never happens. The zone that holds a name is the longest
//! suffix of the name the provider holds as a zone, so the search walks
//! the name's labels up, one at a time, and stops at the first zone the
//! provider holds.
//!
//! The search is a property of the name and the provider, not of one
//! call site: the TLSA refresh after a certificate changed and the
//! dns-01 challenge of an ACME order both write a record whose name is
//! below the zone the credential is scoped to.

use crate::dns::provider::{DnsProvider, ProviderError};

/// The zones that could hold `name`, longest first: the name itself, then
/// the name without its leftmost label, and so on, down to the last two
/// labels. A zone has a domain and a top-level label at least, and no
/// provider holds a top-level label as a zone.
pub fn candidates(name: &str) -> Vec<String> {
	let name = name.trim_end_matches('.').to_ascii_lowercase();
	let labels: Vec<&str> = name.split('.').collect();
	let mut candidates = Vec::new();
	for start in 0..labels.len().saturating_sub(1) {
		candidates.push(labels[start..].join("."));
	}
	candidates
}

/// The zone that holds `name` in `provider`: the longest of the candidates
/// the provider holds as a zone.
///
/// A provider that holds none of them — one that does not name zones, or a
/// credential that cannot see them — gets the name itself, the way the
/// write worked before the search existed: the provider then refuses the
/// write with the zone it could not find, and the message names the name
/// the operator has to fix.
///
/// A provider that could not answer stops the search: a zone that did not
/// answer is not a zone that is not there, and a record written in the
/// parent zone is a record in a zone the operator did not ask for. The
/// error is returned as it is.
pub async fn resolve(provider: &dyn DnsProvider, name: &str) -> Result<String, ProviderError> {
	for candidate in candidates(name) {
		match provider.has_zone(&candidate).await {
			Ok(true) => return Ok(candidate),
			Ok(false) => {}
			Err(error) => return Err(error),
		}
	}
	Ok(name.to_string())
}

#[cfg(test)]
#[path = "zone_tests.rs"]
mod tests;
