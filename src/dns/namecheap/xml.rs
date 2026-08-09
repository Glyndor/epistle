//! Wire types for the subset of the Namecheap XML API we read, plus the
//! bounded body read that protects against an oversize response.

use quick_xml::de::from_str;
use serde::Deserialize;

use super::super::provider::{DnsRecord, ProviderError, RecordKind};
use super::MAX_BODY;

/// One record as Namecheap returns it from `getHosts` (and as we re-emit it
/// to `setHosts`). `address` carries the kind-specific payload verbatim — for
/// TXT that includes the surrounding quotes Namecheap stores.
#[derive(Clone, Deserialize)]
pub(crate) struct Host {
	#[serde(rename = "@Name", default)]
	pub(crate) name: String,
	#[serde(rename = "@Type", default)]
	pub(crate) kind: String,
	#[serde(rename = "@Address", default)]
	pub(crate) address: String,
	#[serde(rename = "@TTL", default)]
	pub(crate) ttl: u32,
	#[serde(rename = "@MXPref", default)]
	pub(crate) mx_pref: Option<u16>,
	#[serde(rename = "@Priority", default)]
	pub(crate) priority: Option<u16>,
	#[serde(rename = "@Weight", default)]
	pub(crate) weight: Option<u16>,
	#[serde(rename = "@Port", default)]
	pub(crate) port: Option<u16>,
}

#[derive(Deserialize)]
pub(crate) struct ApiResponse {
	#[serde(rename = "@Status")]
	pub(crate) status: String,
	#[serde(rename = "Errors", default)]
	pub(crate) errors: Option<ErrorsBlock>,
	#[serde(rename = "CommandResponse", default)]
	pub(crate) command_response: Option<CommandResponse>,
}

#[derive(Deserialize)]
pub(crate) struct ErrorsBlock {
	#[serde(rename = "Error", default)]
	pub(crate) errors: Vec<ApiError>,
}

#[derive(Deserialize)]
pub(crate) struct ApiError {
	#[serde(rename = "@Number", default)]
	pub(crate) number: String,
	#[serde(rename = "$text", default)]
	pub(crate) text: String,
}

#[derive(Deserialize)]
pub(crate) struct CommandResponse {
	#[serde(rename = "DomainDNSGetHostsResult", default)]
	pub(crate) hosts_result: Option<HostsResult>,
}

#[derive(Deserialize)]
pub(crate) struct HostsResult {
	#[serde(rename = "host", default)]
	pub(crate) hosts: Vec<Host>,
}

/// Namecheap API error numbers we treat as auth failures (the operator's IP
/// is not on the whitelist, or the API key is disabled). All other error
/// numbers surface as [`ProviderError::Remote`] with the provider's text.
const AUTH_ERROR_NUMBERS: &[&str] = &["1012801", "1012802", "2011169"];

/// Read a response body in chunks with a hard cap.
pub(crate) async fn read_bounded(mut response: reqwest::Response) -> Result<String, ProviderError> {
	let mut body = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|e| ProviderError::Remote(e.to_string()))?
	{
		if body.len() + chunk.len() > MAX_BODY {
			return Err(ProviderError::Remote("namecheap response too large".into()));
		}
		body.extend_from_slice(&chunk);
	}
	String::from_utf8(body).map_err(|e| ProviderError::Remote(e.to_string()))
}

/// Pull the hosts list out of an [`ApiResponse`]. Returns an empty `Vec`
/// when the response has no `CommandResponse` or hosts block.
pub(crate) fn extract_hosts(api: ApiResponse) -> Vec<Host> {
	let cmd = match api.command_response {
		Some(c) => c,
		None => return Vec::new(),
	};
	let hosts_result = match cmd.hosts_result {
		Some(h) => h,
		None => return Vec::new(),
	};
	hosts_result.hosts
}

/// Read the body with a cap and parse it as an [`ApiResponse`], mapping HTTP
/// and Namecheap-level errors to typed errors.
pub(crate) async fn parse_response(
	response: reqwest::Response,
) -> Result<ApiResponse, ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	if !status.is_success() {
		return Err(ProviderError::Remote(format!("HTTP {status}")));
	}
	let body = read_bounded(response).await?;
	let api: ApiResponse = from_str(&body).map_err(|e| ProviderError::Remote(e.to_string()))?;
	if api.status.eq_ignore_ascii_case("ERROR") {
		let first = api
			.errors
			.and_then(|e| e.errors.into_iter().next())
			.unwrap_or(ApiError {
				number: String::new(),
				text: "namecheap api error".into(),
			});
		if AUTH_ERROR_NUMBERS.iter().any(|n| *n == first.number) {
			return Err(ProviderError::Auth);
		}
		return Err(ProviderError::Remote(if first.text.is_empty() {
			format!("namecheap error {}", first.number)
		} else {
			first.text
		}));
	}
	Ok(api)
}

/// Convert a [`Host`] back into the abstract [`DnsRecord`] form. Returns
/// `None` for kinds we do not model (e.g. URLFRAME, ALIAS — Namecheap has a
/// few aliases we never publish).
pub(crate) fn host_to_record(host: Host, zone: &str) -> Option<DnsRecord> {
	let kind = match host.kind.as_str() {
		"A" => RecordKind::A,
		"AAAA" => RecordKind::Aaaa,
		"CNAME" => RecordKind::Cname,
		"TXT" => RecordKind::Txt,
		"MX" => RecordKind::Mx,
		"SRV" => RecordKind::Srv,
		_ => return None,
	};
	let value = match kind {
		RecordKind::Txt => host.address.trim_matches('"').to_string(),
		RecordKind::Mx => {
			let p = host.mx_pref?;
			format!("{} {}", p, host.address.trim_end_matches('.'))
		}
		RecordKind::Srv => {
			let p = host.priority?;
			let w = host.weight?;
			let port = host.port?;
			format!(
				"{} {} {} {}",
				p,
				w,
				port,
				host.address.trim_end_matches('.')
			)
		}
		_ => host.address.trim_end_matches('.').to_string(),
	};
	let name = if host.name == "@" {
		zone.to_string()
	} else {
		format!("{}.{}", host.name, zone)
	};
	Some(DnsRecord {
		name,
		kind,
		value,
		ttl: host.ttl,
	})
}
