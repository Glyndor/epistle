//! Client autodiscovery documents and the HTTP endpoints that serve them.
//!
//! A client configures itself from just an email address by fetching a config
//! document: Thunderbird's autoconfig `clientConfig` XML and Microsoft's
//! Autodiscover v1 POX XML. Operators point `autoconfig.<domain>` and
//! `autodiscover.<domain>` at this listener (behind their TLS proxy). The same
//! pure builders back the `mail autoconfig` / `mail autodiscover` CLI commands.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Build the Thunderbird autoconfig `clientConfig` document for `domain`: IMAP
/// over implicit TLS (993) and SMTP submission over STARTTLS (587),
/// authenticated with the full email address.
pub fn autoconfig(domain: &str, hostname: &str) -> String {
	let domain = escape(domain);
	let host = escape(hostname);
	format!(
		r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
	<emailProvider id="{domain}">
		<domain>{domain}</domain>
		<displayName>{domain} mail</displayName>
		<displayShortName>{domain}</displayShortName>
		<incomingServer type="imap">
			<hostname>{host}</hostname>
			<port>993</port>
			<socketType>SSL</socketType>
			<authentication>password-cleartext</authentication>
			<username>%EMAILADDRESS%</username>
		</incomingServer>
		<outgoingServer type="smtp">
			<hostname>{host}</hostname>
			<port>587</port>
			<socketType>STARTTLS</socketType>
			<authentication>password-cleartext</authentication>
			<username>%EMAILADDRESS%</username>
		</outgoingServer>
	</emailProvider>
</clientConfig>
"#
	)
}

/// Build the Microsoft Autodiscover v1 POX response: IMAP over implicit TLS
/// (993) and SMTP submission over STARTTLS (587), both authenticated.
pub fn autodiscover(hostname: &str) -> String {
	let host = escape(hostname);
	format!(
		r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
	<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
		<Account>
			<AccountType>email</AccountType>
			<Action>settings</Action>
			<Protocol>
				<Type>IMAP</Type>
				<Server>{host}</Server>
				<Port>993</Port>
				<SSL>on</SSL>
				<Encryption>SSL</Encryption>
				<SPA>off</SPA>
				<AuthRequired>on</AuthRequired>
			</Protocol>
			<Protocol>
				<Type>SMTP</Type>
				<Server>{host}</Server>
				<Port>587</Port>
				<SSL>on</SSL>
				<Encryption>TLS</Encryption>
				<SPA>off</SPA>
				<AuthRequired>on</AuthRequired>
			</Protocol>
		</Account>
	</Response>
</Autodiscover>
"#
	)
}

/// Build a Microsoft Autodiscover v2 JSON response for the requested protocol,
/// or `None` if the protocol is not supported. `Autodiscoverv1` redirects to the
/// POX endpoint; IMAP/POP use implicit TLS, SMTP submission uses STARTTLS.
pub fn autodiscover_v2(hostname: &str, protocol: &str) -> Option<String> {
	let host = json_escape(hostname);
	if protocol.eq_ignore_ascii_case("autodiscoverv1") {
		return Some(format!(
			r#"{{"Protocol":"Autodiscoverv1","Url":"https://{host}/autodiscover/autodiscover.xml"}}"#
		));
	}
	let (proto, port, ssl) = match protocol.to_ascii_lowercase().as_str() {
		"imap" => ("IMAP", 993, true),
		"pop" => ("POP3", 995, true),
		"smtp" => ("SMTP", 587, false),
		_ => return None,
	};
	Some(format!(
		r#"{{"Protocol":"{proto}","Server":"{host}","Port":{port},"SSL":{ssl},"AuthRequired":true}}"#
	))
}

/// Escape a value for safe interpolation into a JSON string literal.
fn json_escape(value: &str) -> String {
	value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape the five XML special characters for safe interpolation.
pub fn escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

/// The domain part of an `emailaddress` query value, lowercased.
fn domain_of(email: &str) -> Option<String> {
	email
		.rsplit_once('@')
		.map(|(_, domain)| domain.trim().to_ascii_lowercase())
		.filter(|domain| !domain.is_empty())
}

/// Shared handler state: the mail hostname and the hosted domains (lowercased).
#[derive(Clone)]
struct Discovery {
	hostname: String,
	domains: Arc<[String]>,
}

/// Router serving the autoconfig/autodiscover documents.
pub fn router(hostname: String, domains: Vec<String>) -> Router {
	let state = Discovery {
		hostname,
		domains: domains
			.iter()
			.map(|d| d.to_ascii_lowercase())
			.collect::<Vec<_>>()
			.into(),
	};
	Router::new()
		.route("/mail/config-v1.1.xml", get(autoconfig_handler))
		.route(
			"/.well-known/autoconfig/mail/config-v1.1.xml",
			get(autoconfig_handler),
		)
		.route(
			"/autodiscover/autodiscover.xml",
			get(autodiscover_handler).post(autodiscover_handler),
		)
		.route(
			"/autodiscover/autodiscover.json",
			get(autodiscover_v2_handler),
		)
		.with_state(state)
}

fn xml(body: String) -> Response {
	([(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn json(body: String) -> Response {
	([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// Case-insensitive query-parameter lookup (Outlook sends `Protocol`/`Email`).
fn param_ci<'a>(params: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
	params
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case(key))
		.map(|(_, v)| v)
}

/// Serve Thunderbird autoconfig for the `emailaddress` query's domain, if hosted.
async fn autoconfig_handler(
	State(state): State<Discovery>,
	Query(params): Query<HashMap<String, String>>,
) -> Response {
	let Some(domain) = params.get("emailaddress").and_then(|e| domain_of(e)) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	if !state.domains.contains(&domain) {
		return StatusCode::NOT_FOUND.into_response();
	}
	xml(autoconfig(&domain, &state.hostname))
}

/// Serve the Microsoft Autodiscover v1 document (keyed on the mail hostname).
async fn autodiscover_handler(State(state): State<Discovery>) -> Response {
	xml(autodiscover(&state.hostname))
}

/// Serve the Microsoft Autodiscover v2 JSON document for the requested
/// `Protocol`. A hosted `Email` domain is required when supplied; an
/// unsupported protocol is a 404.
async fn autodiscover_v2_handler(
	State(state): State<Discovery>,
	Query(params): Query<HashMap<String, String>>,
) -> Response {
	let Some(protocol) = param_ci(&params, "Protocol") else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	if let Some(domain) = param_ci(&params, "Email").and_then(|e| domain_of(e))
		&& !state.domains.contains(&domain)
	{
		return StatusCode::NOT_FOUND.into_response();
	}
	match autodiscover_v2(&state.hostname, protocol) {
		Some(body) => json(body),
		None => StatusCode::NOT_FOUND.into_response(),
	}
}

#[cfg(test)]
#[path = "autodiscovery_tests.rs"]
mod tests;
