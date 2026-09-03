//! S3 implementation of [`BlobBackend`]. Signs every request with
//! AWS Signature Version 4 (no SDK dependency — `aws-sdk-s3` is a tree of
//! modules for four verbs; SigV4 is small enough to own) and maps the four
//! HTTP verbs S3 exposes to the four [`BlobBackend`] methods:
//!
//! - `PutObject` → `put`
//! - `GetObject` → `get` (404 → `Ok(None)`, 401/403 → `BlobError::Auth`)
//! - `DeleteObject` → `delete` (404 → `Ok(())`)
//! - `ListObjectsV2` → `list` (the payload keys only; sidecars skipped)
//!
//! Object key layout mirrors the on-disk one: `<id>` for the payload,
//! `<id><suffix>` for sidecars (`""`, `".type"`, `".owner"`). The id is a
//! UUID, which is shell- and URL-safe as a key segment; no encoding needed.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::BlobBackend;
use super::BlobError;
use super::sigv4;

/// `Send + Sync` future alias specific to this module. Uses `'static` (with
/// the per-call state cloned into the `async move`) so the four verbs have
/// the same lifetime pattern, mirroring `OvhProvider::upsert`.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// Internal state every async call needs. Cloneable so each trait method can
/// snapshot the configuration into its own future.
#[derive(Clone)]
struct Inner {
	client: reqwest::Client,
	endpoint: String,
	bucket: String,
	region: String,
	access_key_id: String,
	secret_access_key: String,
}

/// An S3-backed blob store. Owners of `S3Backend` see only the public
/// constructor; the inner state is a single `Arc<Inner>` so cloning the
/// service for a task is a refcount bump.
pub struct S3Backend {
	inner: Arc<Inner>,
}

impl S3Backend {
	/// Build the backend for one bucket. The endpoint is whatever URL the
	/// operator sets (`https://s3.us-east-1.amazonaws.com`, an S3-compatible
	/// service like MinIO at `http://minio.local:9000`, etc.); path-style
	/// addressing is used so the URL is deterministic regardless of the
	/// endpoint host style. S3 and every S3-compatible service accept
	/// path-style.
	pub fn new(
		endpoint: String,
		bucket: String,
		region: String,
		access_key_id: String,
		secret_access_key: String,
	) -> Self {
		S3Backend {
			inner: Arc::new(Inner {
				client: reqwest::Client::new(),
				endpoint,
				bucket,
				region,
				access_key_id,
				secret_access_key,
			}),
		}
	}

	/// The S3 object key for `(id, suffix)`. `suffix` is `""` for the payload
	/// and `".type"` / `".owner"` for the sidecars — exactly what the on-disk
	/// layout uses.
	fn key(&self, id: Uuid, suffix: &str) -> String {
		format!("{id}{suffix}")
	}

	/// The bucket-scoped host header (`<bucket>.<endpoint-host>`). When S3
	/// serves the request through virtual-hosted addressing the `Host:`
	/// header is what tells it which bucket; the mock tests assert against
	/// the same value.
	fn host_header(inner: &Inner) -> String {
		let host = inner
			.endpoint
			.trim_start_matches("https://")
			.trim_start_matches("http://")
			.trim_end_matches('/');
		format!("{}.{}", inner.bucket, host)
	}

	/// Path-style URL for an object key.
	fn object_url(inner: &Inner, key: &str) -> String {
		let endpoint = inner.endpoint.trim_end_matches('/');
		format!("{endpoint}/{}/{}", inner.bucket, key)
	}

	/// Compute the four SigV4-signed values for an object-level verb whose
	/// canonical request has no query string.
	fn signed_object_headers(
		inner: &Inner,
		method: &str,
		key: &str,
		payload: &[u8],
	) -> SignedObjectHeaders {
		let host_header = Self::host_header(inner);
		let epoch = current_epoch();
		let (amz_date, date_stamp) = sigv4::timestamps(epoch);
		let payload_hash = sigv4::sha256_hex(payload);
		let canonical_uri = format!("/{}/{}", inner.bucket, key);
		let canonical_headers = format!(
			"host:{host_header}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
		);
		let signed = "host;x-amz-content-sha256;x-amz-date";
		let canonical_request =
			format!("{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed}\n{payload_hash}");
		let scope = format!("{date_stamp}/{}/{}/aws4_request", inner.region, "s3");
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
			sigv4::sha256_hex(canonical_request.as_bytes())
		);
		let key_material =
			sigv4::signing_key(&inner.secret_access_key, &date_stamp, &inner.region, "s3");
		let sig = sigv4::signature(&key_material, &string_to_sign);
		let authorization = format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
			inner.access_key_id
		);
		SignedObjectHeaders {
			host: host_header,
			amz_date,
			payload_hash,
			authorization,
		}
	}

	/// Translate an HTTP response status to success / typed error. 401/403
	/// are the auth case; other non-2xx is generic.
	fn check(response: reqwest::Response) -> Result<(), BlobError> {
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(BlobError::Auth);
		}
		if !status.is_success() {
			return Err(BlobError::Remote(format!("HTTP {status}")));
		}
		Ok(())
	}
}

/// The four values an object-level request needs. Bundled together so the
/// four `BlobBackend` verbs all build it the same way.
struct SignedObjectHeaders {
	host: String,
	amz_date: String,
	payload_hash: String,
	authorization: String,
}

impl BlobBackend for S3Backend {
	fn get(&self, id: Uuid, suffix: &str) -> BoxFuture<'static, Option<Vec<u8>>> {
		let inner = self.inner.clone();
		let key = self.key(id, suffix);
		Box::pin(async move {
			let url = Self::object_url(&inner, &key);
			let hdr = Self::signed_object_headers(&inner, "GET", &key, &[]);
			let response = inner
				.client
				.get(&url)
				.header("x-amz-date", &hdr.amz_date)
				.header(reqwest::header::AUTHORIZATION, &hdr.authorization)
				.header("x-amz-content-sha256", &hdr.payload_hash)
				.header(reqwest::header::HOST, &hdr.host)
				.send()
				.await
				.map_err(|error| BlobError::Remote(error.to_string()))?;
			let status = response.status();
			if status == reqwest::StatusCode::NOT_FOUND {
				return Ok(None);
			}
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(BlobError::Auth);
			}
			if !status.is_success() {
				return Err(BlobError::Remote(format!("HTTP {status}")));
			}
			let bytes = response
				.bytes()
				.await
				.map_err(|error| BlobError::Remote(error.to_string()))?;
			Ok(Some(bytes.to_vec()))
		})
	}

	fn put(&self, id: Uuid, suffix: &str, bytes: &[u8]) -> BoxFuture<'static, ()> {
		let inner = self.inner.clone();
		let key = self.key(id, suffix);
		let payload = bytes.to_vec();
		Box::pin(async move {
			let url = Self::object_url(&inner, &key);
			let hdr = Self::signed_object_headers(&inner, "PUT", &key, &payload);
			let response = inner
				.client
				.put(&url)
				.header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
				.header("x-amz-date", &hdr.amz_date)
				.header(reqwest::header::AUTHORIZATION, &hdr.authorization)
				.header("x-amz-content-sha256", &hdr.payload_hash)
				.header(reqwest::header::HOST, &hdr.host)
				.body(payload)
				.send()
				.await
				.map_err(|error| BlobError::Remote(error.to_string()))?;
			Self::check(response)
		})
	}

	fn delete(&self, id: Uuid, suffix: &str) -> BoxFuture<'static, ()> {
		let inner = self.inner.clone();
		let key = self.key(id, suffix);
		Box::pin(async move {
			let url = Self::object_url(&inner, &key);
			let hdr = Self::signed_object_headers(&inner, "DELETE", &key, &[]);
			let response = inner
				.client
				.delete(&url)
				.header("x-amz-date", &hdr.amz_date)
				.header(reqwest::header::AUTHORIZATION, &hdr.authorization)
				.header("x-amz-content-sha256", &hdr.payload_hash)
				.header(reqwest::header::HOST, &hdr.host)
				.send()
				.await
				.map_err(|error| BlobError::Remote(error.to_string()))?;
			// 204 (Deleted) and 404 (NoSuchKey) are both success here:
			// `delete` is idempotent.
			let status = response.status();
			if status == reqwest::StatusCode::NOT_FOUND {
				return Ok(());
			}
			Self::check(response)
		})
	}

	fn list(&self) -> BoxFuture<'static, Vec<Uuid>> {
		let inner = self.inner.clone();
		Box::pin(async move {
			// `ListObjectsV2` paginates; walk until the response stops
			// handing back a continuation token. The mock tests against the
			// same JSON shape.
			let mut next_continuation: Option<String> = None;
			let mut out = Vec::new();
			loop {
				let host_header = Self::host_header(&inner);
				let (url_with_query, canonical_query) = match &next_continuation {
					Some(token) => (
						format!(
							"{}/{}/?continuation-token={}&list-type=2",
							inner.endpoint.trim_end_matches('/'),
							inner.bucket,
							urlencode(token),
						),
						format!("continuation-token={}&list-type=2", urlencode(token)),
					),
					None => (
						format!(
							"{}/{}/?list-type=2",
							inner.endpoint.trim_end_matches('/'),
							inner.bucket,
						),
						"list-type=2".to_string(),
					),
				};
				let epoch = current_epoch();
				let (amz_date, date_stamp) = sigv4::timestamps(epoch);
				let payload_hash = sigv4::sha256_hex(&[]);
				let canonical_uri = format!("/{}/", inner.bucket);
				let canonical_headers = format!(
					"host:{host_header}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
				);
				let signed = "host;x-amz-content-sha256;x-amz-date";
				let canonical_request = format!(
					"GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload_hash}"
				);
				let scope = format!("{date_stamp}/{}/{}/aws4_request", inner.region, "s3");
				let string_to_sign = format!(
					"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
					sigv4::sha256_hex(canonical_request.as_bytes())
				);
				let key_material =
					sigv4::signing_key(&inner.secret_access_key, &date_stamp, &inner.region, "s3");
				let sig = sigv4::signature(&key_material, &string_to_sign);
				let authorization = format!(
					"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
					inner.access_key_id
				);

				let response = inner
					.client
					.get(&url_with_query)
					.header("x-amz-date", &amz_date)
					.header(reqwest::header::AUTHORIZATION, &authorization)
					.header("x-amz-content-sha256", &payload_hash)
					.header(reqwest::header::HOST, &host_header)
					.send()
					.await
					.map_err(|error| BlobError::Remote(error.to_string()))?;
				if response.status() == reqwest::StatusCode::UNAUTHORIZED
					|| response.status() == reqwest::StatusCode::FORBIDDEN
				{
					return Err(BlobError::Auth);
				}
				if !response.status().is_success() {
					return Err(BlobError::Remote(format!("HTTP {}", response.status())));
				}
				// Parse the body as JSON manually: enabling reqwest's
				// `json` feature would pull in serde_json at the
				// crate-boundary level, which is overkill for one call.
				let body_bytes = response
					.bytes()
					.await
					.map_err(|error| BlobError::Remote(error.to_string()))?;
				let body: ListResponse = serde_json::from_slice(&body_bytes)
					.map_err(|error| BlobError::Remote(error.to_string()))?;
				for entry in body.contents {
					// Sidecars end with `.type` or `.owner`; skip them so
					// `list` returns payload ids only. The check happens
					// before splitting because the payload stem (a UUID) is
					// also a valid UUID stem for `<uuid>.type`, so a naive
					// `split('.')` would land both on the same id.
					if entry.key.ends_with(".type") || entry.key.ends_with(".owner") {
						continue;
					}
					if let Ok(id) = Uuid::parse_str(&entry.key) {
						out.push(id);
					}
				}
				match body.next_continuation_token {
					Some(token) if !token.is_empty() => next_continuation = Some(token),
					_ => break,
				}
			}
			Ok(out)
		})
	}
}

/// The JSON body S3 returns from `ListObjectsV2`. We only need the keys and
/// whether more pages follow; serde fills the rest with `#[serde(default)]`
/// so a future S3 release adding fields does not break parsing.
#[derive(serde::Deserialize)]
struct ListResponse {
	#[serde(default, rename = "Contents")]
	contents: Vec<ListEntry>,
	#[serde(default, rename = "NextContinuationToken")]
	next_continuation_token: Option<String>,
}

/// One entry inside `ListBucketResult.Contents`: the object key, plus
/// metadata we do not need but must tolerate on the wire.
#[derive(serde::Deserialize)]
struct ListEntry {
	#[serde(rename = "Key")]
	key: String,
}

/// Percent-encode without touching unreserved characters S3 already accepts.
/// S3 is tolerant; this avoids `reqwest::Url` re-ordering or rewriting the
/// path under us, which would break the canonical request the signature is
/// computed against.
fn urlencode(input: &str) -> String {
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
fn current_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

#[cfg(test)]
#[path = "s3_backend_tests.rs"]
mod tests;
