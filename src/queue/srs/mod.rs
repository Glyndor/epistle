//! Sender Rewriting Scheme (SRS) for forwarded mail.
//!
//! When we forward a message (a Sieve `redirect`, an alias), keeping the
//! original envelope sender makes the forwarded mail fail SPF at the next hop,
//! since we are not an authorized sender for that domain. SRS rewrites the
//! envelope sender into a local, HMAC-signed address (`SRS0=...@ourdomain`) so
//! SPF passes; a bounce to that address is validated and rewritten back to the
//! original sender. This is the pure encode/decode core.

use ring::hmac;

/// Base32 alphabet (RFC 4648) for the timestamp field.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// The timestamp wraps every 1024 days (two base32 characters).
const TS_MODULUS: u64 = 1024;

/// A fresh secret for one domain: 32 bytes from the system CSPRNG, as
/// URL-safe base64 (43 characters). `None` only if the system has no entropy.
pub fn generate_secret() -> Option<String> {
	use base64::Engine;
	let bytes = ring::rand::generate::<[u8; 32]>(&ring::rand::SystemRandom::new()).ok()?;
	Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.expose()))
}

/// Rewrites and validates SRS sender addresses with a shared secret.
pub struct Srs {
	key: hmac::Key,
}

impl Srs {
	/// Build a rewriter from a secret. The same secret must be used to forward
	/// and to validate returning bounces.
	pub fn new(secret: &[u8]) -> Self {
		Srs {
			key: hmac::Key::new(hmac::HMAC_SHA256, secret),
		}
	}

	/// Rewrite `local@domain` into an `SRS0` address at `our_domain`. `now_days`
	/// is the current day number (UNIX seconds / 86400).
	pub fn forward(&self, local: &str, domain: &str, our_domain: &str, now_days: u64) -> String {
		let ts = encode_timestamp(now_days);
		let hash = self.hash(None, &ts, domain, local);
		format!("SRS0={hash}={ts}={domain}={local}@{our_domain}")
	}

	/// Like [`forward`](Self::forward), for mail that a hosted domain's
	/// account forwards: the address names `hosted` (`SRS0.<hosted>=...`) and
	/// the HMAC covers it, so an address made for one hosted domain does not
	/// verify as another's even under the same secret.
	pub fn forward_for(
		&self,
		hosted: &str,
		(local, domain): (&str, &str),
		our_domain: &str,
		now_days: u64,
	) -> String {
		let hosted = hosted.to_ascii_lowercase();
		let ts = encode_timestamp(now_days);
		let hash = self.hash(Some(&hosted), &ts, domain, local);
		format!("SRS0.{hosted}={hash}={ts}={domain}={local}@{our_domain}")
	}

	/// Validate and reverse an `SRS0` local-part back to `(local, domain)`.
	/// Returns `None` if the address is malformed, the HMAC does not match, or
	/// the timestamp is older than `max_age_days` (or implausibly far future).
	/// An address that names a hosted domain is for
	/// [`reverse_for`](Self::reverse_for), never for this method.
	pub fn reverse(
		&self,
		srs_local: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<(String, String)> {
		let rest = strip_prefix_ci(srs_local, "SRS0=")?;
		self.reverse_fields(None, rest, now_days, max_age_days)
	}

	/// Validate and reverse an `SRS0.<hosted>=...` local-part made by
	/// [`forward_for`](Self::forward_for) for exactly `hosted`.
	pub fn reverse_for(
		&self,
		hosted: &str,
		srs_local: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<(String, String)> {
		let (named, rest) = split_hosted(srs_local)?;
		if !named.eq_ignore_ascii_case(hosted) {
			return None;
		}
		self.reverse_fields(
			Some(&named.to_ascii_lowercase()),
			rest,
			now_days,
			max_age_days,
		)
	}

	/// `hash=ts=domain=local`, where local may itself contain '='.
	fn reverse_fields(
		&self,
		scope: Option<&str>,
		rest: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<(String, String)> {
		let mut parts = rest.splitn(4, '=');
		let hash = parts.next()?;
		let ts = parts.next()?;
		let domain = parts.next()?;
		let local = parts.next()?;
		if domain.is_empty() || local.is_empty() {
			return None;
		}
		let stamp = decode_timestamp(ts)?;

		// Constant-time compare of the recomputed hash.
		let expected = self.hash(scope, ts, domain, local);
		if !constant_time_eq(expected.as_bytes(), hash.as_bytes()) {
			return None;
		}

		if timestamp_age(stamp, now_days) > max_age_days {
			return None;
		}
		Some((local.to_string(), domain.to_string()))
	}

	/// First four base64 characters of HMAC over the lowercased
	/// `ts=domain=local`, preceded by `hosted|` when the address names a
	/// hosted domain.
	fn hash(&self, hosted: Option<&str>, ts: &str, domain: &str, local: &str) -> String {
		use base64::Engine;
		let scope = hosted.map(|name| format!("{name}|")).unwrap_or_default();
		let data = format!("{scope}{ts}={domain}={local}").to_ascii_lowercase();
		let tag = hmac::sign(&self.key, data.as_bytes());
		let encoded = base64::engine::general_purpose::STANDARD.encode(tag.as_ref());
		encoded.chars().take(4).collect()
	}
}

/// Two base32 characters encoding `days mod 1024`.
fn encode_timestamp(days: u64) -> String {
	let value = (days % TS_MODULUS) as usize;
	let hi = BASE32[(value >> 5) & 31] as char;
	let lo = BASE32[value & 31] as char;
	format!("{hi}{lo}")
}

/// Decode a two-character base32 timestamp into `days mod 1024`.
fn decode_timestamp(ts: &str) -> Option<u64> {
	let bytes = ts.as_bytes();
	if bytes.len() != 2 {
		return None;
	}
	let hi = base32_value(bytes[0])?;
	let lo = base32_value(bytes[1])?;
	Some((hi as u64) * 32 + lo as u64)
}

fn base32_value(c: u8) -> Option<u8> {
	BASE32
		.iter()
		.position(|&b| b == c.to_ascii_uppercase())
		.map(|p| p as u8)
}

/// How many days old a wrapped timestamp is relative to now (mod 1024). A
/// timestamp slightly in the future (clock skew) reads as nearly a full cycle
/// old, which `max_age_days` rejects.
fn timestamp_age(stamp: u64, now_days: u64) -> u64 {
	let now = now_days % TS_MODULUS;
	(now + TS_MODULUS - stamp) % TS_MODULUS
}

/// Split `SRS0.<hosted>=rest` into the hosted domain and `rest`. The name is
/// a DNS-name shape only: it picks which secret verifies the address, and
/// the HMAC is what proves it.
pub(crate) fn split_hosted(srs_local: &str) -> Option<(&str, &str)> {
	let after = strip_prefix_ci(srs_local, "SRS0.")?;
	let (hosted, rest) = after.split_once('=')?;
	let plausible = !hosted.is_empty()
		&& hosted
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
	plausible.then_some((hosted, rest))
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
	// `get` answers `None` when the cut falls inside a multibyte character, where slicing
	// would panic on an address chosen by whoever sent the mail.
	let head = text.get(..prefix.len())?;
	head.eq_ignore_ascii_case(prefix)
		.then(|| &text[prefix.len()..])
}

/// Length-aware constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b) {
		diff |= x ^ y;
	}
	diff == 0
}

mod keys;
pub use keys::SrsKeys;

#[cfg(test)]
mod tests;
