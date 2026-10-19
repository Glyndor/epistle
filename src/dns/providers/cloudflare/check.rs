//! Read-only Cloudflare token inspection. Remote diagnostics are never echoed.

use serde::Deserialize;
use serde_json::Value;

use super::CloudflareProvider;
use crate::dns::provider::ProviderError;
use crate::dns::providers::check::{AccessReport, Finding, covers, failure_cause};
use crate::net::HttpsUrl;

mod policy;

#[derive(Deserialize)]
struct Envelope<T> {
	success: bool,
	result: T,
	#[serde(default)]
	result_info: Option<PageInfo>,
}

#[derive(Deserialize)]
struct PageInfo {
	page: usize,
	total_pages: usize,
	total_count: usize,
}

#[derive(Deserialize)]
struct Token {
	id: String,
	status: String,
	expires_on: Option<String>,
	not_before: Option<String>,
}

#[derive(Deserialize)]
struct Zone {
	id: String,
	name: String,
}

impl CloudflareProvider {
	async fn inspect_get<T: serde::de::DeserializeOwned>(
		&self,
		url: HttpsUrl,
	) -> Result<Envelope<T>, ProviderError> {
		let response = self
			.client
			.get(url.into_url())
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(crate::dns::providers::transport)?;
		let status = response.status();
		if matches!(status.as_u16(), 401 | 403) {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {}", status.as_u16())));
		}
		let text = crate::dns::providers::read_body(response).await?;
		let body: Envelope<T> = serde_json::from_str(&text).map_err(|_| invalid())?;
		if !body.success {
			return Err(invalid());
		}
		Ok(body)
	}

	async fn inspect_zones(&self) -> Result<Vec<Zone>, ProviderError> {
		let mut zones = Vec::new();
		let mut ids = std::collections::BTreeSet::new();
		let mut names = std::collections::BTreeSet::new();
		let mut expected = None;
		for page in 1..=crate::dns::providers::LIST_MAX_PAGES {
			let url = self
				.base
				.with_segments(["zones"])?
				.with_query("per_page", "50")
				.with_query("page", &page.to_string());
			let body: Envelope<Vec<Zone>> = self.inspect_get(url).await?;
			let info = body.result_info.ok_or_else(invalid)?;
			if page == 1
				&& info.page == 1
				&& info.total_pages == 0
				&& info.total_count == 0
				&& body.result.is_empty()
			{
				return Ok(zones);
			}
			if info.page != page
				|| info.total_pages > crate::dns::providers::LIST_MAX_PAGES
				|| info.total_pages < page
				|| info.total_count > crate::dns::providers::LIST_MAX_RECORDS
				|| expected.is_some_and(|value| value != (info.total_pages, info.total_count))
				|| (body.result.is_empty() && page < info.total_pages)
			{
				return Err(invalid());
			}
			expected = Some((info.total_pages, info.total_count));
			for zone in body.result {
				if !valid_id(&zone.id)
					|| crate::domain::normalize(&zone.name).is_err()
					|| zone.name.contains(self.secret.token())
					|| !ids.insert(zone.id.clone())
					|| !names.insert(zone.name.to_ascii_lowercase())
				{
					return Err(invalid());
				}
				zones.push(zone);
			}
			if zones.len() > info.total_count {
				return Err(invalid());
			}
			if page == info.total_pages {
				return if zones.len() == info.total_count {
					Ok(zones)
				} else {
					Err(invalid())
				};
			}
		}
		Err(invalid())
	}

	pub(super) async fn check_inner(
		&self,
		names: &[String],
	) -> Result<AccessReport, ProviderError> {
		let mut report = AccessReport::unknown();
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let token = self
			.inspect_get::<Token>(self.base.with_segments(["user", "tokens", "verify"])?)
			.await;
		let mut policies = None;
		match token {
			Ok(body) => {
				let token = body.result;
				report.token_status = token_finding(&token, now);
				report.expiry = expiry(token.expires_on.as_deref(), now);
				if valid_id(&token.id) {
					match self
						.inspect_get::<policy::Details>(
							self.base.with_segments(["user", "tokens", &token.id])?,
						)
						.await
					{
						Ok(body) => policies = body.result.policies,
						Err(ProviderError::Auth) => {
							report.record_write = Finding::unknown(
								"token policies are not readable with this credential",
							);
							report.scope = report.record_write.clone();
						}
						Err(error) => {
							report.record_write = Finding::failure(failure_cause(&error));
							report.scope = report.record_write.clone();
						}
					}
				}
			}
			Err(error) => {
				report.token_status = Finding::failure(failure_cause(&error));
				report.expiry = report.token_status.clone();
			}
		}
		match self.inspect_zones().await {
			Ok(zones) => {
				let (finding, needed) = zone_finding(&zones, names);
				report.zones = finding;
				if !needed.is_empty() {
					report.record_read =
						Finding::verified("records can be read in each visible required zone");
					for zone in &needed {
						let url = self
							.records_url(&zone.id, None)?
							.with_query("per_page", "1");
						if let Err(error) = self.inspect_get::<Vec<Value>>(url).await {
							report.record_read = Finding::failure(failure_cause(&error));
							break;
						}
					}
				}
				if let Some(policies) = policies {
					(report.record_write, report.scope) =
						policy::findings(&policies, &zones, &needed);
				}
			}
			Err(error) => {
				report.zones = Finding::failure(failure_cause(&error));
				report.record_read = report.zones.clone();
			}
		}
		if report.token_status.status == crate::dns::providers::check::Outcome::Failure {
			report.record_write = Finding::failure(
				"token activity could not be verified; write permission is not established",
			);
		}
		Ok(report)
	}
}

fn invalid() -> ProviderError {
	ProviderError::Remote("invalid inspection response".into())
}

fn valid_id(id: &str) -> bool {
	id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn timestamp(text: &str) -> Option<u64> {
	// Bound and constrain the spelling before using the shared calendar parser.
	if !(20..=40).contains(&text.len())
		|| !text
			.bytes()
			.all(|b| b.is_ascii_digit() || b"TtZz:+-.".contains(&b))
	{
		return None;
	}
	let bytes = text.as_bytes();
	if bytes[4] != b'-'
		|| bytes[7] != b'-'
		|| bytes[10] != b'T'
		|| bytes[13] != b':'
		|| bytes[16] != b':'
		|| ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
			.iter()
			.all(|range| bytes[range.clone()].iter().all(u8::is_ascii_digit))
		|| text[17..19].parse::<u8>().ok()? > 59
	{
		return None;
	}
	let tail = &text[19..];
	let tail = if let Some(fraction) = tail.strip_prefix('.') {
		let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
		if digits == 0 {
			return None;
		}
		&fraction[digits..]
	} else {
		tail
	};
	if tail != "Z"
		&& !(tail.len() == 6
			&& matches!(tail.as_bytes()[0], b'+' | b'-')
			&& tail.as_bytes()[3] == b':'
			&& tail[1..3].bytes().all(|b| b.is_ascii_digit())
			&& tail[4..6].bytes().all(|b| b.is_ascii_digit())
			&& tail[1..3].parse::<u8>().ok()? <= 23
			&& tail[4..6].parse::<u8>().ok()? <= 59)
	{
		return None;
	}
	crate::storage::delivery_log::parse_rfc3339(text).ok()
}

fn token_finding(token: &Token, now: u64) -> Finding {
	if token.status != "active" {
		return Finding::failure("token is expired, disabled or has an unknown status");
	}
	if let Some(date) = &token.expires_on {
		match timestamp(date) {
			Some(time) if time > now => {}
			Some(_) => return Finding::failure("token has expired"),
			None => return Finding::failure("provider returned an invalid expiration date"),
		}
	}
	if let Some(date) = &token.not_before {
		match timestamp(date) {
			Some(time) if time <= now => {}
			Some(_) => return Finding::failure("token is not active yet"),
			None => return Finding::failure("provider returned an invalid activation date"),
		}
	}
	Finding::verified("token is active")
}

fn expiry(value: Option<&str>, now: u64) -> Finding {
	let Some(value) = value else {
		return Finding::unknown("provider did not expose an expiration date");
	};
	let Some(time) = timestamp(value) else {
		return Finding::failure("provider returned an invalid expiration date");
	};
	let date = crate::clock::rfc3339(time);
	if time <= now {
		Finding::failure(format!("expired at {date}"))
	} else if time - now <= 7 * 86_400 {
		Finding::verified(format!("expires at {date}; expires within seven days"))
	} else {
		Finding::verified(format!("expires at {date}"))
	}
}

fn zone_finding<'a>(zones: &'a [Zone], names: &[String]) -> (Finding, Vec<&'a Zone>) {
	let mut needed: Vec<&Zone> = Vec::new();
	let mut missing = Vec::new();
	for name in names {
		if let Some(zone) = zones
			.iter()
			.filter(|z| covers(&z.name, name))
			.max_by_key(|z| z.name.len())
		{
			if !needed.iter().any(|old| old.id == zone.id) {
				needed.push(zone);
			}
		} else {
			missing.push(name.as_str());
		}
	}
	let visible = zones.iter().map(|z| z.name.as_str()).collect::<Vec<_>>();
	let extra = zones
		.iter()
		.filter(|z| !needed.iter().any(|n| n.id == z.id))
		.map(|z| z.name.as_str())
		.collect::<Vec<_>>();
	let detail = format!(
		"visible zones: {}; extra zones: {}; own names not visible: {}",
		visible.join(", "),
		extra.join(", "),
		missing.join(", ")
	);
	let finding = if missing.is_empty() {
		Finding::verified(detail)
	} else {
		Finding::failure(detail)
	};
	(finding, needed)
}

#[cfg(test)]
#[path = "check_http_tests.rs"]
mod http_tests;
#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
