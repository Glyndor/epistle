//! The signed requests of the OVH provider and the record lookups built on them.

use super::*;

impl OvhProvider {
	/// Send a signed request and parse the JSON body; map 401/403 to `Auth`
	/// and any other non-2xx to `Remote`.
	pub(super) async fn send_json<T: serde::de::DeserializeOwned>(
		&self,
		method: reqwest::Method,
		url: &HttpsUrl,
		body: &str,
	) -> Result<T, ProviderError> {
		let text = self.send(method, url, body).await?;
		serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
	}

	/// Send a signed request and read the body as text. Useful when the body
	/// may be empty (PUT/DELETE/refresh) — the parser for JSON would choke.
	pub(super) async fn send(
		&self,
		method: reqwest::Method,
		url: &HttpsUrl,
		body: &str,
	) -> Result<String, ProviderError> {
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign(method.as_str(), url.as_str(), body, ts);
		let response = self
			.client
			.request(method, url.as_url().clone())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.body(body.to_string())
			.send()
			.await
			.map_err(transport)?;
		let zone = zone_of(&self.base, url);
		check_status(&response, zone.as_deref())?;
		crate::dns::providers::read_body(response).await
	}

	/// Variant that ignores the response body (PUT, DELETE, /refresh).
	pub(super) async fn send_unit(
		&self,
		method: reqwest::Method,
		url: &HttpsUrl,
		body: &str,
	) -> Result<(), ProviderError> {
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign(method.as_str(), url.as_str(), body, ts);
		let response = self
			.client
			.request(method, url.as_url().clone())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.body(body.to_string())
			.send()
			.await
			.map_err(transport)?;
		let zone = zone_of(&self.base, url);
		check_status(&response, zone.as_deref())?;
		Ok(())
	}

	/// Find the first record at `sub_domain` of `kind`. Returns `None` if
	/// there are none — used to decide between POST and PUT on upsert, and
	/// to detect "already gone" on delete. When `value` is `Some`, the
	/// match is `same_txt_purpose`-based for TXT (so the existing tagged
	/// record is updated in place) and exact-match for the first record
	/// otherwise. A `None` value keeps the first-by-(kind, sub) selection.
	pub(super) async fn find_record_id(
		&self,
		zone: &str,
		sub_domain: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<Option<u64>, ProviderError> {
		let url = self.find_url(zone, kind, sub_domain)?;
		let ids: Vec<u64> = self.send_json(reqwest::Method::GET, &url, "").await?;
		let Some(target_value) = value else {
			return Ok(ids.into_iter().next());
		};
		// OVH's list endpoint only returns ids, so the value-bearing
		// path fans out one detail GET per id to read the target and
		// match it. The number of records at a single (kind, sub) is
		// expected to be small (one or two ACME challenges at most), so
		// the fanout stays bounded.
		for id in ids {
			let Some(rec) = self.get_record(zone, id).await? else {
				continue;
			};
			if same_txt_purpose(&rec.target, target_value) {
				return Ok(Some(id));
			}
		}
		Ok(None)
	}

	/// Every record id that would match a single-record lookup
	/// (`find_record_id`); used by the TXT upsert path to collapse
	/// duplicates of the same purpose.
	pub(super) async fn find_record_ids(
		&self,
		zone: &str,
		sub_domain: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<impl Iterator<Item = u64>, ProviderError> {
		let url = self.find_url(zone, kind, sub_domain)?;
		let ids: Vec<u64> = self.send_json(reqwest::Method::GET, &url, "").await?;
		let mut out: Vec<u64> = Vec::new();
		for id in ids {
			let Some(rec) = self.get_record(zone, id).await? else {
				continue;
			};
			let matches = match value {
				Some(v) => same_txt_purpose(&rec.target, v),
				None => true,
			};
			if matches {
				out.push(id);
			}
		}
		Ok(out.into_iter())
	}

	/// Fetch one record by id; returns `None` if OVH says 404 (the record
	/// was removed out from under us between the list and the fetch).
	pub(super) async fn get_record(
		&self,
		zone: &str,
		id: u64,
	) -> Result<Option<OvhRecord>, ProviderError> {
		let url = self.zone_url(zone, &["record", &id.to_string()])?;
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign("GET", url.as_str(), "", ts);
		let response = self
			.client
			.get(url.into_url())
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = crate::dns::providers::read_body(response).await?;
		let rec: OvhRecord =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		Ok(Some(rec))
	}

	/// POST `/domain/zone/{z}/refresh` after every write so the change
	/// reaches OVH's authoritative nameservers.
	pub(super) async fn refresh_zone(&self, zone: &str) -> Result<(), ProviderError> {
		let url = self.zone_url(zone, &["refresh"])?;
		self.send_unit(reqwest::Method::POST, &url, "").await
	}
}
