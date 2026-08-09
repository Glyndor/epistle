//! Shared mock infrastructure for the Namecheap provider tests. The mock
//! pretends to be the Namecheap XML API: it returns a configurable body for
//! `getHosts` and a configurable status/body for `setHosts`, and captures
//! every URL and POST body for assertions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;

use super::super::provider::{DnsRecord, RecordKind, ScopedSecret};
use super::NamecheapProvider;

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
	/// Captured POST bodies for `setHosts` calls, in order.
	pub(super) set_hosts_bodies: Vec<String>,
}

pub(super) type Shared = Arc<Mutex<MockState>>;

pub(super) const EMPTY_ZONE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.org"/></CommandResponse></ApiResponse>"#;

pub(super) const OK_XML: &str =
	r#"<?xml version="1.0" encoding="UTF-8"?><ApiResponse Status="OK"><Errors/></ApiResponse>"#;

pub(super) async fn handle(
	State(state): State<Shared>,
	method: axum::http::Method,
	uri: axum::http::Uri,
	Query(params): Query<HashMap<String, String>>,
	body: String,
) -> axum::http::Response<String> {
	let url = uri.to_string();
	let command = params.get("Command").cloned().unwrap_or_default();
	let mut s = state.lock().unwrap();
	s.urls.push(url);
	if method == axum::http::Method::POST {
		s.set_hosts_bodies.push(body);
	}
	match command.as_str() {
		"namecheap.domains.dns.getHosts" => {
			let xml = if s.get_hosts_xml.is_empty() {
				EMPTY_ZONE_XML.to_string()
			} else {
				s.get_hosts_xml.clone()
			};
			xml_response(200, &xml)
		}
		"namecheap.domains.dns.setHosts" => {
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
		.with_api_url(format!("http://{addr}/xml.response"));
	(provider, state)
}

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}
