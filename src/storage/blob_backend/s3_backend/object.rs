//! Object-level verbs: one signed request per key for get, put and delete.

use std::sync::Arc;

use super::limits::read_capped;
use super::{BlobError, BoxFuture, Inner, S3Backend};

impl S3Backend {
	/// `GetObject` for one key: `None` on 404.
	pub(super) fn get_key(inner: Arc<Inner>, key: String) -> BoxFuture<'static, Option<Vec<u8>>> {
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
			Ok(Some(read_capped(response, inner.limits.object).await?))
		})
	}

	/// `PutObject` for one key.
	pub(super) fn put_key(
		inner: Arc<Inner>,
		key: String,
		payload: Vec<u8>,
	) -> BoxFuture<'static, ()> {
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

	/// `DeleteObject` for one key; a missing key is success.
	pub(super) fn delete_key(inner: Arc<Inner>, key: String) -> BoxFuture<'static, ()> {
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
}
