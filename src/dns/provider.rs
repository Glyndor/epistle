//! Pluggable DNS provider abstraction for record automation, with
//! scoped-secret handling for provider API tokens.
//!
//! The [`DnsProvider`] trait is object-safe and test-injectable, so the DNS
//! wizard, ACME DNS-01, and record auto-publish can be written against it and
//! exercised with an in-memory fake. [`ManualProvider`] is the always-available
//! default that needs no credentials. [`ScopedSecret`] holds a provider token
//! restricted to a single zone (least privilege) and never logs it.

use std::path::Path;
use std::pin::Pin;

/// A DNS record kind epistle publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
	A,
	Aaaa,
	Txt,
	Mx,
	Cname,
	Tlsa,
	Srv,
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
		}
	}
}

/// A DNS record to publish or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
	/// Fully-qualified record name (e.g. `_dmarc.example.org`).
	pub name: String,
	pub kind: RecordKind,
	pub value: String,
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

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DNS provider that can publish and remove records in a zone. Object-safe
/// and test-injectable (mirrors the [`crate::spf::DnsLookup`] pattern).
pub trait DnsProvider: Send + Sync {
	/// Create or replace `record` in `zone`.
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_>;
	/// Remove `record` from `zone` (idempotent).
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
