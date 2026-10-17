//! One module per DNS provider epistle can publish records through. Each
//! provider lives in its own directory with its tests; what they share (the
//! `DnsProvider` trait, record types, matching rules) is in
//! [`crate::dns::provider`].

/// The most pages a provider listing reads. A server that keeps handing out
/// pages (or claims a million of them) cannot keep a listing going for ever,
/// and a listing that stops at the cap is an error, not a shorter zone: a
/// delegation that fell off the end would be written over.
pub(crate) const LIST_MAX_PAGES: usize = 1000;

/// The most records a provider listing returns, for the same reason.
pub(crate) const LIST_MAX_RECORDS: usize = 100_000;

/// The error a listing returns when it hits [`LIST_MAX_PAGES`] or
/// [`LIST_MAX_RECORDS`].
pub(crate) fn listing_too_long(zone: &str) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(format!(
		"the {zone} zone is larger than a listing reads ({LIST_MAX_PAGES} pages, {LIST_MAX_RECORDS} records)"
	))
}

/// A transport failure as a provider error. The request URL is left out of the
/// message: some providers carry a credential in it (Namecheap's `ApiKey`), and
/// the message reaches a terminal, a log and a support screenshot.
pub(crate) fn transport(error: reqwest::Error) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(error.without_url().to_string())
}

pub mod bunny;
pub mod cloudflare;
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod gcloud;
pub mod godaddy;
pub mod namecheap;
pub mod ovh;
pub mod porkbun;
pub mod rfc2136;
pub mod route53;
pub mod spaceship;

#[cfg(test)]
pub(crate) mod listing_contract;

#[cfg(test)]
mod transport_tests;
