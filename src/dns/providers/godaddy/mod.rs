//! A GoDaddy DNS provider implementing [`DnsProvider`]. The v1 API expects
//! `Authorization: sso-key <api_key>:<api_secret>` and replaces the whole
//! record set at `(type, name)` with `PUT /domains/{domain}/records/{type}/{name}`.
//! A list of records is a single JSON array; the body the upsert path builds
//! holds one element per call because the [`DnsProvider`] trait takes a single
//! [`DnsRecord`] at a time. MX/SRV need their extra fields (`priority` for MX,
//! `priority`/`weight`/`port`/`service`/`protocol` for SRV) on the array
//! element. The apex is the literal `@`.
//!
//! GoDaddy restricts production API access by account eligibility; a 403 is
//! not a bad key but a "your account is not enabled for production API" verdict,
//! so the error message spells that out instead of the generic
//! `provider authentication failed` the other providers return for 403.
//!
//! Endpoints and payloads follow <https://developer.godaddy.com/doc/endpoints/dns>.
//!
//! [`DnsProvider`]: crate::dns::provider::DnsProvider
//! [`DnsRecord`]: crate::dns::provider::DnsRecord

mod errors;
mod list;
mod lock;
mod provider;
mod records;
mod requests;
mod write;

pub use provider::GodaddyProvider;

#[cfg(test)]
mod tests;
