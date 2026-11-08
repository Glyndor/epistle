//! The AWS signature of the Route 53 requests.

use super::*;

impl Route53Provider {
	/// The SigV4 `Authorization` header for a POST with this body.
	pub(super) fn authorization(
		&self,
		path: &str,
		body: &str,
		amz_date: &str,
		date: &str,
	) -> String {
		let payload_hash = sha256_hex(body.as_bytes());
		// Host and x-amz-date are signed; headers must be sorted, lowercased.
		let canonical_headers = format!("host:{HOST}\nx-amz-date:{amz_date}\n");
		let signed_headers = "host;x-amz-date";
		let canonical_request =
			format!("POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
		let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
			sha256_hex(canonical_request.as_bytes())
		);
		let sig = signature(&self.secret_key, date, REGION, SERVICE, &string_to_sign);
		format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
			self.access_key
		)
	}

	/// SigV4 authorization for a GET (the same shape; the canonical
	/// request swaps `POST` for `GET`).
	pub(super) fn authorization_get(
		&self,
		path: &str,
		query: &str,
		amz_date: &str,
		date: &str,
	) -> String {
		let payload_hash = sha256_hex(b"");
		let canonical_headers = format!("host:{HOST}\nx-amz-date:{amz_date}\n");
		let signed_headers = "host;x-amz-date";
		let canonical_request =
			format!("GET\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
		let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
			sha256_hex(canonical_request.as_bytes())
		);
		let sig = signature(&self.secret_key, date, REGION, SERVICE, &string_to_sign);
		format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
			self.access_key
		)
	}
}
