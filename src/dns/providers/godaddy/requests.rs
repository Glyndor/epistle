//! Authenticated record-set HTTP requests.

use crate::dns::provider::ProviderError;
use crate::dns::providers::transport;
use crate::net::HttpsUrl;

use super::GodaddyProvider;
use super::errors::{auth_error, check};

impl GodaddyProvider {
	/// A request with the `sso-key` header attached. The header carries the
	/// credentials in the form `<api_key>:<api_secret>`, key first, secret
	/// second. A wrong order makes GoDaddy answer 401, which the other
	/// providers' 401 path treats as a missing token.
	pub(super) fn auth_header(&self) -> String {
		format!("sso-key {}:{}", self.api_key, self.api_secret)
	}

	/// `{base}/domains/{zone}/records[/{type}/{name}]`, with the zone and the
	/// record name each escaped as one path segment.
	pub(super) fn records_url(&self, set: Option<(&str, &str)>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["domains", self.zone.as_str(), "records"];
		if let Some((kind, rel)) = set {
			segments.extend([kind, rel]);
		}
		Ok(self.base.with_segments(segments)?)
	}

	/// `PUT /domains/{domain}/records/{type}/{name}`, replace the entire
	/// record set at `(type, name)` with `body`. GoDaddy replies 200 on
	/// success; the body is empty.
	pub(super) async fn put_records(
		&self,
		kind: &str,
		rel: &str,
		body: String,
	) -> Result<(), ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
		let response = self
			.client
			.put(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	/// `GET /domains/{domain}/records/{type}/{name}`, the current record
	/// set at `(type, name)`. Returns an empty array when no records
	/// exist. Used by the upsert and delete paths so they can merge
	/// against the live set rather than PUT the singleton element the
	/// caller asked for (GoDaddy's PUT replaces the whole set, a
	/// singleton PUT would wipe every other value at the same
	/// `(type, name)`).
	pub(super) async fn fetch_set(
		&self,
		kind: &str,
		rel: &str,
	) -> Result<Vec<serde_json::Value>, ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
		let path = url.as_url().path().to_string();
		let response = self
			.client
			.get(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(auth_error(status));
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = crate::dns::providers::read_body(response).await?;
		// The body is not echoed into the error: an HTTP 200 with a
		// diagnostic body (the response from a misbehaving gateway) can
		// carry credentials that belong in the `Authorization` header we
		// just sent, and `Display`/`Debug` on `ProviderError::Remote`
		// exposes the string verbatim to operators. The status and the
		// endpoint are enough to act on; the body shape (non-array,
		// parse error) is reported as a flag, not as the value.
		match serde_json::from_str::<serde_json::Value>(&text) {
			Ok(serde_json::Value::Array(items)) => Ok(items),
			Ok(_) => Err(ProviderError::Remote(format!(
				"GET {path} returned a non-array body"
			))),
			Err(_) => Err(ProviderError::Remote(format!(
				"GET {path} returned an unparseable body"
			))),
		}
	}

	/// `DELETE /domains/{domain}/records/{type}/{name}`, remove every
	/// record at that `(type, name)`. GoDaddy replies 204.
	pub(super) async fn delete_records(&self, kind: &str, rel: &str) -> Result<(), ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
		let response = self
			.client
			.delete(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}
}
