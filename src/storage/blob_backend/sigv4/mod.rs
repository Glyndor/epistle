//! AWS Signature Version 4 for the S3 blob backend.
//!
//! Computes the `Authorization` header for an S3 request, and the matching
//! `x-amz-content-sha256` and `x-amz-date` headers, against a secret access
//! key. Implemented by hand (no `aws-sdk-s3` dependency) because the SDK is
//! a tree of modules for the four HTTP verbs we want from it; the algorithm
//! is small enough that the surface we own is smaller than the surface we
//! would inherit.
//!
//! The signature vector in `tests` matches the one AWS publishes for IAM's
//! "Task 3: Calculate the signature" (same primitives, same constants):
//! a working unit test against a published vector catches a silent change to
//! the HMAC chain, the way `OvhProvider::sign` carries a vector against
//! python-ovh's reference.

use std::fmt::Write as _;

/// One HMAC-SHA256 step. The SigV4 chain is `k_date → k_region → k_service
/// → k_signing`, each consuming the previous key.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
	let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
	ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// Lowercase hex of a digest or HMAC tag.
fn hex_lower(bytes: &[u8]) -> String {
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(out, "{byte:02x}");
	}
	out
}

/// The SigV4 signing key, derived once per (date, region, service) triple so
/// the per-request work is a single HMAC rather than a chain of four.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
	let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
	let k_region = hmac(&k_date, region.as_bytes());
	let k_service = hmac(&k_region, service.as_bytes());
	hmac(&k_service, b"aws4_request")
}

/// The HMAC-SHA256 tag, hex-encoded, of `string_to_sign` under `signing_key`.
pub fn signature(signing_key: &[u8], string_to_sign: &str) -> String {
	hex_lower(&hmac(signing_key, string_to_sign.as_bytes()))
}

/// The hex-encoded SHA-256 digest of `payload`. Empty / streaming payloads
/// pass `&[]`; S3 also accepts the literal string `UNSIGNED-PAYLOAD` here,
/// which the server then hashes itself (useful for very large objects); this
/// module always signs the actual payload because uploaded blobs are small
/// enough that the cost is irrelevant.
pub fn sha256_hex(payload: &[u8]) -> String {
	hex_lower(ring::digest::digest(&ring::digest::SHA256, payload).as_ref())
}

/// The two timestamps SigV4 wants: `YYYYMMDDTHHMMSSZ` ("amz-date") and
/// `YYYYMMDD` (the credential scope's date stamp).
pub fn timestamps(epoch_seconds: u64) -> (String, String) {
	let days = epoch_seconds / 86_400;
	let secs = epoch_seconds % 86_400;
	let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
	let (y, mo, d) = civil_from_days(days as i64);
	(
		format!("{y:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z"),
		format!("{y:04}{mo:02}{d:02}"),
	)
}

/// Howard Hinnant's civil-from-days algorithm: convert a day count since the
/// Unix epoch to a `(year, month, day)`. UTC throughout, leap seconds
/// ignored (SigV4 does not see them either — the operator's `x-amz-date` is
/// wall-clock UTC at second granularity).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	(if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests;
