//! One module per DNS provider epistle can publish records through. Each
//! provider lives in its own directory with its tests; what they share (the
//! `DnsProvider` trait, record types, matching rules) is in
//! [`crate::dns::provider`].

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
