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

/// The zone to write `record_name` in, proved to be the one that serves it.
///
/// [`resolve`] finds the longest zone of `host` the credential can see.
/// That is a statement about access, not about DNS: when the child zone
/// is delegated to other nameservers and the credential only sees the
/// parent, the parent still holds the name, and a record written there is
/// one no validator ever reads. The zone is therefore listed, and a zone
/// cut (an NS rrset below the apex) at or above `record_name` refuses the
/// write: the failure names the cut, and nothing is written.
///
/// A provider that cannot list its zone ([`ProviderError::Unsupported`])
/// gives no delegation to read, so the zone it names is the one the
/// operator configured for the credential and is taken as it is.
pub async fn resolve_serving(
	provider: &dyn DnsProvider,
	host: &str,
	record_name: &str,
) -> Result<String, ProviderError> {
	let zone = resolve(provider, host).await?;
	let listing = match provider.list(&zone).await {
		Ok(listing) => listing,
		Err(ProviderError::Unsupported) => return Ok(zone),
		Err(error) => return Err(error),
	};
	refuse_if_delegated(&zone, record_name, &listing)?;
	Ok(zone)
}

/// Refuse a write of `record_name` in `zone` when `listing`, the records
/// the provider returned, delegates the name. An NS rrset at a name that is
/// `record_name` or above it (two labels at least) hands the name to other
/// nameservers, and a record written here would never be served.
///
/// The cuts are read from every NS in the listing, not only from those under
/// `zone`: a provider that does not bind a listing to the zone asked for
/// (it answers for the account, or for a parent) describes a zone other than
/// the one the lookup accepted, and cuts computed against `zone` alone would
/// miss the delegation. An NS is the apex of its own zone, and no cut, only
/// when it is at `zone` itself or the listing proves the apex with an SOA at
/// that name. Anything else is treated as a cut: the write fails closed. The
/// failure names the highest such name.
pub fn refuse_if_delegated(
	zone: &str,
	record_name: &str,
	listing: &[crate::dns::provider::DnsRecord],
) -> Result<(), ProviderError> {
	use crate::dns::names::{canonical_name, in_domain};
	use crate::dns::provider::RecordKind;

	let zone = canonical_name(zone);
	let record = canonical_name(record_name);
	let is_soa = |kind: &RecordKind| matches!(kind, RecordKind::Other(token) if token == "SOA");
	let apexes: Vec<String> = listing
		.iter()
		.filter(|r| is_soa(&r.kind))
		.map(|r| canonical_name(&r.name))
		.collect();
	let cut = listing
		.iter()
		.filter(|r| r.kind == RecordKind::Ns)
		.map(|r| canonical_name(&r.name))
		.filter(|name| name.contains('.') && !name.starts_with("*."))
		.filter(|name| *name != zone && !apexes.contains(name))
		.filter(|name| in_domain(&record, name))
		.min_by_key(|name| name.len());
	match cut {
		None => Ok(()),
		Some(cut) => Err(ProviderError::Remote(format!(
			"{} is delegated to other nameservers, so the zone {} does not serve it; no record was written there",
			crate::cli::term::sanitize(&cut),
			crate::cli::term::sanitize(&zone),
		))),
	}
}

#[cfg(test)]
mod tests;
