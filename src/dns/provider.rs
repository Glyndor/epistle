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
//! (lowercase, tolerant to surrounding whitespace and the optional
//! wire-form quotes); [`same_txt_purpose`] decides whether two values
//! match under the contract above.

use std::path::Path;
use std::pin::Pin;

/// A DNS record kind epistle publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
	/// IPv4 address record.
	A,
	/// IPv6 address record.
	Aaaa,
	/// Text record. Used for SPF, DMARC, DKIM keys, MTA-STS, TLSRPT, and
	/// ACME DNS-01 challenges.
	Txt,
	/// Mail exchange record.
	Mx,
	/// Canonical name (alias) record.
	Cname,
	/// TLSA association record (RFC 6698) for DANE.
	Tlsa,
	/// Service locator record (RFC 2782).
	Srv,
	/// Certification Authority Authorization (RFC 8659).
	Caa,
}

impl RecordKind {
	/// The record type token used in zone files and provider APIs.
	pub fn as_str(self) -> &'static str {
		match self {
			RecordKind::A => "A",
			RecordKind::Aaaa => "AAAA",
			RecordKind::Txt => "TXT",
			RecordKind::Mx => "MX",
			RecordKind::Cname => "CNAME",
			RecordKind::Tlsa => "TLSA",
			RecordKind::Srv => "SRV",
			RecordKind::Caa => "CAA",
		}
	}
}

/// The four parts of an SRV record, split out from the presentation form
/// `"<prio> <weight> <port> <target>."`. The trailing dot on the target is
/// tolerated (and stripped) so callers can build the value either way. Returns
/// `None` if the value is malformed — providers should treat that as an
/// internal error rather than passing it to the API.
pub fn parse_srv(value: &str) -> Option<(u16, u16, u16, String)> {
	let mut parts = value.split_whitespace();
	let prio: u16 = parts.next()?.parse().ok()?;
	let weight: u16 = parts.next()?.parse().ok()?;
	let port: u16 = parts.next()?.parse().ok()?;
	let target = parts.next()?.trim_end_matches('.').to_string();
	if parts.next().is_some() {
		return None;
	}
	Some((prio, weight, port, target))
}

/// A DNS record to publish or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
	/// Fully-qualified record name (e.g. `_dmarc.example.org`).
	pub name: String,
	/// Record type.
	pub kind: RecordKind,
	/// Record value, formatted the way the provider's API expects for that
	/// kind (raw IPv4/IPv6 for A/AAAA, quoted text for TXT, target host for
	/// MX, etc.).
	pub value: String,
	/// Time-to-live in seconds. Providers translate to their own semantics.
	pub ttl: u32,
}

/// A provider operation failure. Its message never contains the secret token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
	/// The provider does not support writes (e.g. manual mode).
	Unsupported,
	/// Authentication with the provider failed.
	Auth,
	/// A transport or provider-side error.
	Remote(String),
}

impl std::fmt::Display for ProviderError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ProviderError::Unsupported => f.write_str("provider does not support writes"),
			ProviderError::Auth => f.write_str("provider authentication failed"),
			ProviderError::Remote(detail) => write!(f, "provider error: {detail}"),
		}
	}
}

impl std::error::Error for ProviderError {}

/// The TXT version tag at the start of `value`, or `None` when the
/// value is empty or its first token is not a tag epistle recognises.
/// The tag is the substring before the first whitespace or `;`; the
/// comparison is case-insensitive on the way in and the function
/// returns the canonical spec form (`v=spf1`, `v=DMARC1`, `v=DKIM1`,
/// `v=STSv1`, `v=TLSRPTv1`). Leading and trailing whitespace and the
/// optional pair of surrounding double quotes (the wire form some
/// providers use) are tolerated; an empty or whitespace-only value
/// returns `None`.
pub fn txt_purpose(value: &str) -> Option<&'static str> {
	let trimmed = value.trim();
	let stripped = trimmed
		.strip_prefix('"')
		.and_then(|s| s.strip_suffix('"'))
		.unwrap_or(trimmed);
	if stripped.is_empty() {
		return None;
	}
	let head: String = stripped
		.chars()
		.take_while(|c| !c.is_whitespace() && *c != ';')
		.collect();
	match head.to_ascii_lowercase().as_str() {
		"v=spf1" => Some("v=spf1"),
		"v=dmarc1" => Some("v=DMARC1"),
		"v=dkim1" => Some("v=DKIM1"),
		"v=stsv1" => Some("v=STSv1"),
		"v=tlsrptv1" => Some("v=TLSRPTv1"),
		_ => None,
	}
}

/// Whether two TXT values match under the upsert/delete contract
/// (see the module doc). Two tagged values match when their tag is
/// the same; an untagged value matches only an identical value (after
/// the same leading/trailing whitespace and surrounding-quote
/// stripping); a tagged value never matches an untagged one.
pub fn same_txt_purpose(a: &str, b: &str) -> bool {
	match (txt_purpose(a), txt_purpose(b)) {
		(Some(x), Some(y)) => x == y,
		(Some(_), None) | (None, Some(_)) => false,
		(None, None) => normalised_txt(a) == normalised_txt(b),
	}
}

/// Trim surrounding whitespace and one pair of wire-form quotes, the
/// way [`txt_purpose`] does, so two untagged values compare on the
/// same bytes.
fn normalised_txt(value: &str) -> String {
	let trimmed = value.trim();
	trimmed
		.strip_prefix('"')
		.and_then(|s| s.strip_suffix('"'))
		.unwrap_or(trimmed)
		.to_string()
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DNS provider that can publish and remove records in a zone. Object-safe
/// and test-injectable (mirrors the [`crate::spf::DnsLookup`] pattern).
pub trait DnsProvider: Send + Sync {
	/// Create or replace `record` in `zone`. The contract on matching is
	/// spelled out at the top of the module:
	///
	/// - For TXT, `upsert` replaces the TXT with the same purpose (version
	///   tag) at that name and leaves every other TXT at the name alone. A
	///   TXT without a known tag matches only an identical value.
	/// - For every other record kind, `upsert` replaces the whole
	///   `(name, type)` set with the one record in `record`. epistle owns
	///   those names; nothing else is supposed to be writing them.
	///
	/// Implementations are free to issue the minimum number of API calls
	/// that satisfies the contract (e.g. GoDaddy reads the current set,
	/// swaps the matching element, and PUTs the result).
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_>;
	/// Remove `record` from `zone`. Idempotent. The matching rule is the
	/// same as [`DnsProvider::upsert`]:
	///
	/// - For TXT, `delete` with a value removes only the matching record
	///   (same purpose for tagged values, identical value otherwise). An
	///   empty value removes the whole TXT set at the name, the way the
	///   DKIM rotator retires a selector.
	/// - For every other record kind, `delete` removes the whole
	///   `(name, type)` set.
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_>;
	/// List the records epistle manages in `zone`.
	fn list(&self, zone: &str) -> ListOp<'_>;
}

/// Manual mode: no API access. Writes fail with [`ProviderError::Unsupported`]
/// so callers fall back to printing the records for the operator to add by
/// hand. Always available; needs no credentials.
pub struct ManualProvider;

impl DnsProvider for ManualProvider {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A provider API token scoped to a single DNS zone (least privilege). Loaded
/// from an environment variable or a `0600` file; redacted in `Debug` and never
/// logged.
#[derive(Clone)]
pub struct ScopedSecret {
	zone: String,
	token: String,
}

impl ScopedSecret {
	/// A secret for `zone` with an explicit `token`.
	pub fn new(zone: impl Into<String>, token: impl Into<String>) -> Self {
		ScopedSecret {
			zone: zone.into(),
			token: token.into(),
		}
	}

	/// Read the token for `zone` from environment variable `var`. Returns
	/// `None` when the variable is unset or empty.
	pub fn from_env(zone: impl Into<String>, var: &str) -> Option<Self> {
		let token = std::env::var(var).ok()?;
		let token = token.trim();
		(!token.is_empty()).then(|| ScopedSecret::new(zone, token))
	}

	/// Read the token for `zone` from a file that must not be group/world
	/// accessible (`0600`/`0400`), failing closed otherwise.
	pub fn from_file(zone: impl Into<String>, path: &Path) -> std::io::Result<Self> {
		ensure_private(path)?;
		let token = std::fs::read_to_string(path)?.trim().to_string();
		if token.is_empty() {
			return Err(std::io::Error::other("secret file is empty"));
		}
		Ok(ScopedSecret::new(zone, token))
	}

	/// The zone this secret is scoped to.
	pub fn zone(&self) -> &str {
		&self.zone
	}

	/// The token (handle with care; never log it).
	pub fn token(&self) -> &str {
		&self.token
	}

	/// Whether this secret authorizes operating on `name` — only its own zone
	/// or a name within it, never another zone (least privilege).
	pub fn authorizes(&self, name: &str) -> bool {
		let name = name.to_ascii_lowercase();
		let zone = self.zone.to_ascii_lowercase();
		name == zone || name.ends_with(&format!(".{zone}"))
	}
}

impl std::fmt::Debug for ScopedSecret {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ScopedSecret")
			.field("zone", &self.zone)
			.field("token", &"***")
			.finish()
	}
}

/// Fail unless `path` is readable only by its owner (no group/world bits).
#[cfg(unix)]
fn ensure_private(path: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	let mode = std::fs::metadata(path)?.permissions().mode();
	if mode & 0o077 != 0 {
		return Err(std::io::Error::other(format!(
			"secret file {} is group/world-accessible (mode {:#o}); restrict it to 0600",
			path.display(),
			mode & 0o777
		)));
	}
	Ok(())
}

#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> std::io::Result<()> {
	Ok(())
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
