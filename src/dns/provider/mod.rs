//! Pluggable DNS provider abstraction for record automation, with
//! scoped-secret handling for provider API tokens.
//!
//! The [`DnsProvider`] trait is object-safe and test-injectable, so the DNS
//! wizard, ACME DNS-01, and record auto-publish can be written against it and
//! exercised with an in-memory fake. [`ManualProvider`] is the always-available
//! default that needs no credentials. [`ScopedSecret`] holds a provider token
//! restricted to a single zone (least privilege) and never logs it.
//!
//! ## Upsert / delete contract
//!
//! Every provider that publishes records honours the same contract on the
//! name/type/value triple. The contract is what the upper layers can rely on
//! without knowing which provider is wired in.
//!
//! TXT records have a purpose given by their version tag (`v=spf1`,
//! `v=DMARC1`, `v=DKIM1`, `v=STSv1`, `v=TLSRPTv1`). epistle is the only
//! publisher of those tags, so two records with the same tag at the same
//! name are a configuration mistake and the contract treats them as one.
//!
//! - `upsert` replaces the TXT with the same tag at that name and leaves
//!   every other TXT at the name alone.
//! - A TXT without a known tag (an ACME DNS-01 challenge, a domain
//!   verification token) matches only an identical value.
//! - `delete` with a value removes only the matching record by the same
//!   rule.
//! - `delete` with an empty value removes the whole TXT set at that name
//!   (the DKIM rotator retires a selector this way, and selector names
//!   belong to epistle).
//! - Other record types (A, AAAA, MX, SRV, CNAME, TLSA, CAA) keep
//!   whole-set semantics at a name: epistle owns the name and a write
//!   replaces the whole set.
//!
//! The helper [`txt_purpose`] extracts the version tag from a TXT value
//! (lowercase, tolerant to surrounding whitespace and to the quoted
//! presentation form); [`same_txt_purpose`] decides whether two values
//! match under the contract above. How a TXT value is quoted, split and
//! escaped for each provider API lives in [`crate::dns::txt`].
//!
//! ## Guarded contract
//!
//! The upsert and delete contract above says nothing about what the
//! provider found before it wrote, so a write planned against an older
//! listing may destroy the records of somebody else. Three methods carry
//! the guarded contract, and their types live in
//! [`crate::dns::publish::provider`]: [`DnsProvider::publish_snapshot`]
//! lists the zone and says whether the provider applies a guarded change,
//! [`DnsProvider::apply_guarded`] applies a change under a precondition,
//! and [`DnsProvider::lookup_operation`] resolves an operation whose answer
//! was lost. The three default to refusing, so a provider that does not
//! implement them publishes nothing: the default of
//! [`DnsProvider::apply_guarded`] never falls back to `upsert`.

mod contract;
mod errors;
mod kind;
mod manual;
mod record;
mod secret;
mod values;

pub use contract::{DnsProvider, ZoneOp};
pub(crate) use contract::{ListOp, Op};
pub use errors::ProviderError;
pub use kind::{MAX_OTHER_KIND_LEN, RecordKind, UNKNOWN_KIND};
pub use manual::ManualProvider;
pub use record::{DnsRecord, record_description};
pub use secret::ScopedSecret;
pub use values::{mx_target_for_api, parse_srv, same_txt_purpose, txt_purpose, unwrap_quotes};

pub mod live;

#[cfg(test)]
mod tests;
