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

use std::path::Path;
use std::pin::Pin;

/// Free-text description that epistle attaches to every record it creates or
/// updates, for providers whose record API has a per-record description field
/// (Cloudflare `comment`, Bunny `Comment`, Porkbun `notes`). It reads
/// `Epistle v<version>` with the version of the running binary, and every
/// create and every update rewrites it, so a record touched again by a newer
/// release shows the newer version. It is a label for whoever reads the
/// provider's panel, not an ownership key: record matching still uses only
/// type, name and, for TXT, the value. Providers without such a field never
/// receive it. Kept in this one function so the text is easy to extend; it
/// stays well under the tightest documented limit (100 characters on the
/// Cloudflare free plan).
pub fn record_description() -> String {
	format!("Epistle v{}", env!("CARGO_PKG_VERSION"))
}

/// The longest type token [`RecordKind::from_token`] keeps.
pub const MAX_OTHER_KIND_LEN: usize = 32;

/// The token of an [`RecordKind::Other`] whose type a provider returned in
/// a shape no record type has (empty, too long, or with other characters
/// than letters, digits and hyphens).
pub const UNKNOWN_KIND: &str = "UNKNOWN";

/// A DNS record kind. The first eight are what epistle publishes. `Ns`,
/// `Https` and `Svcb` are read back from a zone so a listing keeps them as
/// what they are: an `NS` rrset at a name below the apex is a delegation,
/// and the lockdown must not write anything under it. Every other type a
/// provider returns is kept as [`RecordKind::Other`] with its type token,
/// so a listing never turns a record it does not know into a TXT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecordKind {
	/// IPv4 address record.
	#[serde(rename = "A")]
	A,
	/// IPv6 address record.
	#[serde(rename = "AAAA")]
	Aaaa,
	/// Text record. Used for SPF, DMARC, DKIM keys, MTA-STS, TLSRPT, and
	/// ACME DNS-01 challenges.
	#[serde(rename = "TXT")]
	Txt,
	/// Mail exchange record.
	#[serde(rename = "MX")]
	Mx,
	/// Canonical name (alias) record.
	#[serde(rename = "CNAME")]
	Cname,
	/// TLSA association record (RFC 6698) for DANE.
	#[serde(rename = "TLSA")]
	Tlsa,
	/// Service locator record (RFC 2782).
	#[serde(rename = "SRV")]
	Srv,
	/// Certification Authority Authorization (RFC 8659).
	#[serde(rename = "CAA")]
	Caa,
	/// Name server record. Marks a delegation: any name (other than the
	/// zone apex) that carries NS records is delegated to other
	/// nameservers, and `epistle dns lockdown` must not try to publish
	/// anything under it.
	#[serde(rename = "NS")]
	Ns,
	/// HTTPS RR (RFC 9460): alias for `SVCB` plus a `svcparams` hint,
	/// used at the apex or a service name.
	#[serde(rename = "HTTPS")]
	Https,
	/// Service binding record (RFC 9460).
	#[serde(rename = "SVCB")]
	Svcb,
	/// Any other record type a provider listed (`NAPTR`, `SSHFP`, `LOC`,
	/// ...), with its type token. Build it with [`RecordKind::from_token`], which
	/// bounds the token. Providers refuse to publish or delete it.
	#[serde(rename = "OTHER")]
	Other(String),
}

impl RecordKind {
	/// The kind for a record type token a provider API returned, in any
	/// letter case. Every provider reads its listing through this, so a
	/// type epistle does not publish keeps what it is instead of turning
	/// into a TXT: `NS` is [`RecordKind::Ns`] (a delegation), and a type
	/// with no variant is [`RecordKind::Other`].
	///
	/// The token comes from a remote API, so an `Other` keeps it only when
	/// it can be a record type (ASCII letters, digits and hyphens, at most
	/// [`MAX_OTHER_KIND_LEN`] characters, upper-cased). Anything else
	/// becomes [`UNKNOWN_KIND`], so a hostile token never reaches a
	/// terminal, a log line or a JSON document.
	pub fn from_token(token: &str) -> RecordKind {
		let shaped = !token.is_empty()
			&& token.len() <= MAX_OTHER_KIND_LEN
			&& token
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-');
		if !shaped {
			return RecordKind::Other(UNKNOWN_KIND.to_string());
		}
		let upper = token.to_ascii_uppercase();
		match upper.as_str() {
			"A" => RecordKind::A,
			"AAAA" => RecordKind::Aaaa,
			"TXT" => RecordKind::Txt,
			"MX" => RecordKind::Mx,
			"CNAME" => RecordKind::Cname,
			"TLSA" => RecordKind::Tlsa,
			"SRV" => RecordKind::Srv,
			"CAA" => RecordKind::Caa,
			"NS" => RecordKind::Ns,
			"HTTPS" => RecordKind::Https,
			"SVCB" => RecordKind::Svcb,
			_ => RecordKind::Other(upper),
		}
	}

	/// The record type token used in zone files and provider APIs.
	pub fn as_str(&self) -> &str {
		match self {
			RecordKind::A => "A",
			RecordKind::Aaaa => "AAAA",
			RecordKind::Txt => "TXT",
			RecordKind::Mx => "MX",
			RecordKind::Cname => "CNAME",
			RecordKind::Tlsa => "TLSA",
			RecordKind::Srv => "SRV",
			RecordKind::Caa => "CAA",
			RecordKind::Ns => "NS",
			RecordKind::Https => "HTTPS",
			RecordKind::Svcb => "SVCB",
			RecordKind::Other(name) => name.as_str(),
		}
	}
}

/// `value` without one pair of double quotes that wrap all of it, as a
/// provider that lists every target quoted returns it. A quote that does
/// not wrap the whole value is data (a CAA target is `0 issue "ca.example"`,
/// an HTTPS parameter is `alpn="h2"`) and stays.
pub fn unwrap_quotes(value: &str) -> &str {
	let Some(inner) = value
		.strip_prefix('"')
		.and_then(|rest| rest.strip_suffix('"'))
	else {
		return value;
	};
	// `"a" "b"` starts and ends with a quote and is two strings, not one.
	let mut escaped = false;
	for c in inner.chars() {
		match c {
			'\\' if !escaped => escaped = true,
			'"' if !escaped => return value,
			_ => escaped = false,
		}
	}
	inner
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
	/// Fully-qualified record name (e.g. `_dmarc.example.org`).
	pub name: String,
	/// Record type.
	pub kind: RecordKind,
	/// Record value in presentation form for its kind (raw IPv4/IPv6 for
	/// A/AAAA, target host for MX, etc.). For TXT it is the logical text,
	/// unquoted and unsplit; a value already in quoted presentation form is
	/// accepted and read back through [`crate::dns::txt::txt_logical`].
	/// Each provider encodes it for its own API and every `list` returns
	/// the logical text again.
	pub value: String,
	/// Time-to-live in seconds. Providers translate to their own semantics.
	pub ttl: u32,
	/// Whether the record is proxied through the provider's edge (Cloudflare's
	/// "orange cloud"). Providers that do not proxy (every other one
	/// epistle publishes through) ignore it on write and leave it `None`
	/// on read. Cloudflare populates it from the API's `proxied` field on
	/// `list` and always writes `proxied: false` for mail-related names,
	/// because traffic for SMTP / IMAP / POP3 / submission cannot reach
	/// epistle through the proxy.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proxied: Option<bool>,
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
			// What a provider answered is text from outside: control characters
			// and bidirectional marks in it are escaped before they can reach a
			// terminal, a log or a message.
			ProviderError::Remote(detail) => {
				write!(f, "provider error: {}", crate::cli::term::sanitize(detail))
			}
		}
	}
}

impl std::error::Error for ProviderError {}

impl From<crate::net::HttpsUrlError> for ProviderError {
	fn from(err: crate::net::HttpsUrlError) -> Self {
		ProviderError::Remote(format!("invalid request URL: {err}"))
	}
}

/// The TXT version tag at the start of `value`, or `None` when the
/// value is empty or its first token is not a tag epistle recognises.
/// The tag is the substring before the first whitespace or `;`; the
/// comparison is case-insensitive on the way in and the function
/// returns the canonical spec form (`v=spf1`, `v=DMARC1`, `v=DKIM1`,
/// `v=STSv1`, `v=TLSRPTv1`). The value is read through
/// [`crate::dns::txt::txt_logical`] first, so surrounding whitespace and
/// the presentation form some providers use (one or several quoted
/// strings) are tolerated; an empty or whitespace-only value returns
/// `None`.
pub fn txt_purpose(value: &str) -> Option<&'static str> {
	let stripped = crate::dns::txt::txt_logical(value);
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
/// the same; an untagged value matches only the same logical value
/// ([`crate::dns::txt::same_txt_value`]: whitespace, quoting and
/// 255-octet splitting do not count); a tagged value never matches an
/// untagged one.
pub fn same_txt_purpose(a: &str, b: &str) -> bool {
	match (txt_purpose(a), txt_purpose(b)) {
		(Some(x), Some(y)) => x == y,
		(Some(_), None) | (None, Some(_)) => false,
		(None, None) => crate::dns::txt::same_txt_value(a, b),
	}
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DNS provider that can publish and remove records in a zone. Object-safe
/// and test-injectable (mirrors the [`crate::spf::DnsLookup`] pattern).
pub trait DnsProvider: Send + Sync {
	/// Inspect credential capabilities using read operations only. Unsupported
	/// metadata stays unknown; a successful listing proves only record reading.
	fn check_access<'a>(
		&'a self,
		zone: &'a str,
		_names: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		Box::pin(async move {
			let mut report = crate::dns::providers::check::AccessReport::unknown();
			report.record_read = match self.list(zone).await {
				Ok(_) => crate::dns::providers::check::Finding::verified(
					"records can be read in the configured zone",
				),
				Err(ProviderError::Unsupported) => report.record_read,
				Err(error) => crate::dns::providers::check::Finding::failure(
					crate::dns::providers::check::failure_cause(&error),
				),
			};
			report
		})
	}
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
	fn check_access<'a>(
		&'a self,
		_: &'a str,
		_: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		Box::pin(async { crate::dns::providers::check::AccessReport::unknown() })
	}
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

/// An MX target as a provider API takes it: without the trailing root dot,
/// except the null MX target (RFC 7505), which is the root `.` itself and
/// would otherwise become an empty host.
pub fn mx_target_for_api(target: &str) -> &str {
	if target == "." {
		target
	} else {
		target.trim_end_matches('.')
	}
}

impl DnsRecord {
	/// A record with `proxied: None` (the default for every non-Cloudflare
	/// provider). The convenience constructor exists so call sites that
	/// build a record by hand do not have to spell the field out; tests
	/// already build `DnsRecord` literally.
	pub fn new(
		name: impl Into<String>,
		kind: RecordKind,
		value: impl Into<String>,
		ttl: u32,
	) -> Self {
		Self {
			name: name.into(),
			kind,
			value: value.into(),
			ttl,
			proxied: None,
		}
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
