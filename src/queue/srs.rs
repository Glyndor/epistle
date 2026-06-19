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
		let hash = self.hash(&ts, domain, local);
		format!("SRS0={hash}={ts}={domain}={local}@{our_domain}")
	}

	/// Validate and reverse an `SRS0` local-part back to `(local, domain)`.
	/// Returns `None` if the address is malformed, the HMAC does not match, or
	/// the timestamp is older than `max_age_days` (or implausibly far future).
	pub fn reverse(
		&self,
		srs_local: &str,
		now_days: u64,
		max_age_days: u64,
	) -> Option<(String, String)> {
		let rest = strip_prefix_ci(srs_local, "SRS0=")?;
		// hash=ts=domain=local, where local may itself contain '='.
		let mut parts = rest.splitn(4, '=');
		let hash = parts.next()?;
		let ts = parts.next()?;
		let domain = parts.next()?;
		let local = parts.next()?;
		if domain.is_empty() || local.is_empty() {
			return None;
		}

		// Constant-time compare of the recomputed hash.
		let expected = self.hash(ts, domain, local);
		if !constant_time_eq(expected.as_bytes(), hash.as_bytes()) {
			return None;
		}

		let stamp = decode_timestamp(ts)?;
		if timestamp_age(stamp, now_days) > max_age_days {
			return None;
		}
		Some((local.to_string(), domain.to_string()))
	}

	/// First four base64 characters of HMAC over the lowercased `ts=domain=local`.
	fn hash(&self, ts: &str, domain: &str, local: &str) -> String {
		use base64::Engine;
		let data = format!("{ts}={domain}={local}").to_ascii_lowercase();
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

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
	(text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix))
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

#[cfg(test)]
mod tests {
	use super::*;

	const SECRET: &[u8] = b"a shared srs secret";
	const OUR: &str = "relay.example";

	#[test]
	fn forward_then_reverse_recovers_sender() {
		let srs = Srs::new(SECRET);
		let addr = srs.forward("alice", "example.org", OUR, 19_000);
		assert!(addr.starts_with("SRS0="));
		assert!(addr.ends_with("@relay.example"));
		let local = addr.split_once('@').unwrap().0;
		let (recovered_local, recovered_domain) = srs.reverse(local, 19_000, 7).expect("valid");
		assert_eq!(recovered_local, "alice");
		assert_eq!(recovered_domain, "example.org");
	}

	#[test]
	fn tampered_address_is_rejected() {
		let srs = Srs::new(SECRET);
		let addr = srs.forward("alice", "example.org", OUR, 19_000);
		let local = addr.split_once('@').unwrap().0;
		// Swap the source domain without re-signing.
		let forged = local.replace("example.org", "evil.example");
		assert!(srs.reverse(&forged, 19_000, 7).is_none());
	}

	#[test]
	fn wrong_secret_does_not_validate() {
		let signer = Srs::new(SECRET);
		let addr = signer.forward("alice", "example.org", OUR, 19_000);
		let local = addr.split_once('@').unwrap().0;
		let other = Srs::new(b"different secret");
		assert!(other.reverse(local, 19_000, 7).is_none());
	}

	#[test]
	fn expired_timestamp_is_rejected() {
		let srs = Srs::new(SECRET);
		let addr = srs.forward("alice", "example.org", OUR, 19_000);
		let local = addr.split_once('@').unwrap().0;
		// Ten days later, with a seven-day window.
		assert!(srs.reverse(local, 19_010, 7).is_none());
		// Still valid five days later.
		assert!(srs.reverse(local, 19_005, 7).is_some());
	}

	#[test]
	fn local_part_with_equals_survives() {
		let srs = Srs::new(SECRET);
		let addr = srs.forward("a=b+c", "example.org", OUR, 19_000);
		let local = addr.split_once('@').unwrap().0;
		let (recovered, _) = srs.reverse(local, 19_000, 7).expect("valid");
		assert_eq!(recovered, "a=b+c");
	}

	#[test]
	fn non_srs_address_is_ignored() {
		let srs = Srs::new(SECRET);
		assert!(srs.reverse("plain", 19_000, 7).is_none());
	}
}
