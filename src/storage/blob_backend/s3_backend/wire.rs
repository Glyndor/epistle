//! Wire helpers: the ListObjectsV2 answer, key encoding and the clock SigV4 signs with.

use std::time::{SystemTime, UNIX_EPOCH};

use super::BlobError;

/// The JSON body S3 returns from `ListObjectsV2`. We only need the keys and
/// whether more pages follow; serde fills the rest with `#[serde(default)]`
/// so a future S3 release adding fields does not break parsing.
#[derive(serde::Deserialize)]
pub(super) struct ListResponse {
	#[serde(default, rename = "Contents")]
	pub(super) contents: Vec<ListEntry>,
	#[serde(default, rename = "NextContinuationToken")]
	pub(super) next_continuation_token: Option<String>,
}

/// One entry inside `ListBucketResult.Contents`: the object key, plus
/// metadata we do not need but must tolerate on the wire.
#[derive(serde::Deserialize)]
pub(super) struct ListEntry {
	#[serde(rename = "Key")]
	pub(super) key: String,
}

/// The body of a ListObjectsV2 answer. S3 answers with XML
/// (`ListBucketResult`); a store that answers with the same fields as JSON is
/// read too, so the first character decides.
pub(super) fn parse_list(bytes: &[u8]) -> Result<ListResponse, BlobError> {
	let text = std::str::from_utf8(bytes)
		.map_err(|error| BlobError::Remote(format!("the listing is not text: {error}")))?;
	if text.trim_start().starts_with('<') {
		quick_xml::de::from_str(text).map_err(|error| BlobError::Remote(error.to_string()))
	} else {
		serde_json::from_str(text).map_err(|error| BlobError::Remote(error.to_string()))
	}
}

/// Percent-encode without touching unreserved characters S3 already accepts.
/// S3 is tolerant; this avoids `reqwest::Url` re-ordering or rewriting the
/// path under us, which would break the canonical request the signature is
/// computed against.
pub(super) fn urlencode(input: &str) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(input.len());
	for byte in input.bytes() {
		match byte {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
				out.push(byte as char);
			}
			other => {
				let _ = write!(out, "%{other:02X}");
			}
		}
	}
	out
}

/// Monotonic-ish second counter used as `x-amz-date`. A wall-clock value is
/// what SigV4 wants; the `SystemTime → epoch_seconds` fallback handles
/// clocks set before the Unix epoch (1969) by clamping to zero rather than
/// panicking, which the upload path would do anyway.
pub(super) fn current_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}
