//! Shared mock infrastructure for the Namecheap provider tests. The mock
//! answers the way the documented API does: every call carries the global
//! parameters (`ApiUser`, `ApiKey`, `UserName`, `ClientIp`, `Command`) in
//! the query string or, for a POST, in an `application/x-www-form-urlencoded`
//! body, and `setHosts` takes its hosts as numbered `HostName{n}`,
//! `RecordType{n}`, `Address{n}`, `TTL{n}` and `MXPref{n}` parameters
//! (<https://www.namecheap.com/support/api/methods/domains-dns/set-hosts/>
//! and <https://www.namecheap.com/support/api/global-parameters/>, read
//! 2026-10-12). A request in any other shape gets an `ERROR` response, so
//! a test against this mock fails on a body the real API would refuse.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;

use super::NamecheapProvider;
use crate::dns::provider::{DnsRecord, RecordKind, ScopedSecret};

#[derive(Default)]
pub(super) struct MockState {
	/// What `getHosts` returns (full XML body). When empty, the mock returns
	/// an `OK` response with no hosts (empty zone).
	pub(super) get_hosts_xml: String,
	/// Override for the `setHosts` response: `(status, body)`. When `None`,
	/// the mock returns a default `OK` body with HTTP 200.
	pub(super) set_hosts_response: Option<(u16, String)>,
	/// Captured full URL (`path?query`) of every request, for assertions.
	pub(super) urls: Vec<String>,
	/// Every well-formed `setHosts` call, in order.
	pub(super) set_hosts_calls: Vec<SetHostsCall>,
	/// The content type of every POST, in order.
	pub(super) post_content_types: Vec<String>,
}

/// One `setHosts` call as the mock received it: every parameter, query and
/// form body together.
#[derive(Clone, Debug)]
pub(super) struct SetHostsCall {
	pub(super) params: HashMap<String, String>,
}

/// One host of a `setHosts` call, from its numbered parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SentHost {
	pub(super) name: String,
	pub(super) kind: String,
	pub(super) address: String,
	pub(super) ttl: Option<String>,
	pub(super) mx_pref: Option<String>,
}

impl SetHostsCall {
	/// The hosts, in parameter order.
	pub(super) fn hosts(&self) -> Vec<SentHost> {
		(1..)
			.map_while(|n| {
				let get = |key: &str| self.params.get(&format!("{key}{n}")).cloned();
				Some(SentHost {
					name: get("HostName")?,
					kind: get("RecordType")?,
					address: get("Address")?,
					ttl: get("TTL"),
					mx_pref: get("MXPref"),
				})
			})
			.collect()
	}

	/// One non-numbered parameter.
	pub(super) fn param(&self, key: &str) -> Option<&str> {
		self.params.get(key).map(String::as_str)
	}
}

pub(super) type Shared = Arc<Mutex<MockState>>;

pub(super) const EMPTY_ZONE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"/></CommandResponse></ApiResponse>"#;

pub(super) const OK_XML: &str =
	r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/></ApiResponse>"#;

/// The record types setHosts documents.
const RECORD_TYPES: &[&str] = &[
	"A", "AAAA", "ALIAS", "CAA", "CNAME", "MX", "MXE", "NS", "TXT", "URL", "URL301", "FRAME",
];

fn api_error(text: &str) -> axum::http::Response<String> {
	xml_response(
		200,
		&format!(
			r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="ERROR"><Errors><Error Number="2010324">{text}</Error></Errors></ApiResponse>"#
		),
	)
}

/// Why the documented API would refuse a setHosts call, if it would.
fn refuse_set_hosts(params: &HashMap<String, String>) -> Option<String> {
	for key in ["SLD", "TLD"] {
		if !params.contains_key(key) {
			return Some(format!("Parameter {key} is missing"));
		}
	}
	let call = SetHostsCall {
		params: params.clone(),
	};
	for (n, host) in call.hosts().iter().enumerate() {
		if !RECORD_TYPES.contains(&host.kind.as_str()) {
			return Some(format!("RecordType{} {} is not valid", n + 1, host.kind));
		}
		if host.kind == "MX" && host.mx_pref.is_none() {
			return Some(format!("MXPref{} is missing", n + 1));
		}
	}
	None
}

pub(super) async fn handle(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: axum::http::Uri,
	headers: axum::http::HeaderMap,
	Query(mut params): Query<HashMap<String, String>>,
	body: String,
) -> axum::http::Response<String> {
	let mut s = state.lock().unwrap();
	s.urls.push(uri.to_string());
	if method == axum::http::Method::POST {
		let content_type = headers
			.get(axum::http::header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.unwrap_or("")
			.to_string();
		s.post_content_types.push(content_type.clone());
		if !content_type.starts_with("application/x-www-form-urlencoded") {
			return api_error("POST body is not form parameters");
		}
		params.extend(url::form_urlencoded::parse(body.as_bytes()).into_owned());
	}
	for key in ["ApiUser", "ApiKey", "UserName", "ClientIp", "Command"] {
		if !params.contains_key(key) {
			return api_error(&format!("Parameter {key} is missing"));
		}
	}
	match params["Command"].as_str() {
		"namecheap.domains.dns.getHosts" => {
			let xml = if s.get_hosts_xml.is_empty() {
				EMPTY_ZONE_XML.to_string()
			} else {
				s.get_hosts_xml.clone()
			};
			xml_response(200, &xml)
		}
		"namecheap.domains.dns.setHosts" => {
			if let Some(reason) = refuse_set_hosts(&params) {
				return api_error(&reason);
			}
			s.set_hosts_calls.push(SetHostsCall { params });
			let (status, body) = s
				.set_hosts_response
				.clone()
				.unwrap_or((200, OK_XML.to_string()));
			xml_response(status, &body)
		}
		_ => xml_response(200, OK_XML),
	}
}

pub(super) fn xml_response(status: u16, body: &str) -> axum::http::Response<String> {
	let status = axum::http::StatusCode::from_u16(status).expect("status");
	axum::http::Response::builder()
		.status(status)
		.header(axum::http::header::CONTENT_TYPE, "application/xml")
		.body(body.to_string())
		.expect("build response")
}

/// Start the mock and return (provider pointed at it, shared state). The
/// `get_hosts_xml` is what the mock returns from `getHosts`; leave it empty
/// for an empty zone.
pub(super) async fn mock(
	get_hosts_xml: &str,
	set_hosts_response: Option<(u16, String)>,
) -> (NamecheapProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		get_hosts_xml: get_hosts_xml.to_string(),
		set_hosts_response,
		..Default::default()
	}));
	let app = Router::new()
		.route(
			"/xml.response",
			get(handle).post(handle).put(handle).delete(handle),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = NamecheapProvider::new(ScopedSecret::new("example.org", "user:key"))
		.expect("parse token")
		.with_client_ip(std::net::Ipv4Addr::new(192, 0, 2, 10))
		.with_api_url(
			crate::net::HttpsUrl::loopback_http(&format!("http://{addr}/xml.response")).unwrap(),
		);
	(provider, state)
}

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}
