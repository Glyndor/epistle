//! Tests for the deSEC provider against an in-process axum mock.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::get;

#[derive(Default)]
struct MockState {
	/// rrsets the GET endpoint returns.
	rrsets: serde_json::Value,
	/// Captured PUT bodies.
	puts: Vec<String>,
	/// Last Authorization header seen.
	auth: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

async fn rrsets(
	State(state): State<Shared>,
	method: axum::http::Method,
	headers: axum::http::HeaderMap,
	body: String,
) -> axum::Json<serde_json::Value> {
	let mut s = state.lock().unwrap();
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	if method == axum::http::Method::PUT {
		s.puts.push(body);
		axum::Json(serde_json::json!([]))
	} else {
		axum::Json(s.rrsets.clone())
	}
}

async fn mock(rrsets_json: serde_json::Value) -> (DesecProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		rrsets: rrsets_json,
		..Default::default()
	}));
	let app = Router::new()
		.route("/domains/{zone}/rrsets/", get(rrsets).put(rrsets))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DesecProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}

#[tokio::test]
async fn upsert_puts_quoted_txt_with_correct_subname() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.puts.len(), 1);
	let body = &s.puts[0];
	assert!(body.contains("\"subname\":\"_dmarc\""), "{body}");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	// TXT content is quoted (escaped within the JSON string).
	assert!(body.contains("v=DMARC1; p=none"), "{body}");
	// Token auth, not bearer. `assert_eq!` on `s.auth` would
	// Debug-print the actual API token on a mismatch, dumping
	// the credential into the CI log. The boolean form names
	// the contract without echoing the payload.
	assert!(
		s.auth.as_deref() == Some("Token tok"),
		"the deSEC request must carry the fixture API token"
	);
}

#[tokio::test]
async fn apex_record_uses_empty_subname() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"subname\":\"\""), "{body}");
}

/// An empty-value delete is the DKIM rotator's retire path and must
/// drop the whole rrset, whether it had values or not. With no rrset
/// present, deSEC still gets a PUT with `"records":[]` because that
/// is the wholesale delete the contract asks for.
#[tokio::test]
async fn empty_value_delete_puts_empty_records() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", ""))
		.await
		.expect("delete");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"records\":[]"), "{body}");
}

/// A TXT delete with a value must remove only the matching record
/// and keep siblings at the same owner. Two ACME DNS-01 challenges
/// at the same owner is the canonical case: cleaning up one
/// certificate order's challenge must not wipe the second order's
/// challenge. deSEC's bulk PUT replaces the rrset, so the fix is
/// to read the live rrset, drop the matching value, and PUT the
/// rest (an empty `records` array only when the rrset is fully
/// gone).
#[tokio::test]
async fn txt_delete_with_a_value_keeps_the_sibling_challenge() {
	let rrsets = serde_json::json!([
		{
			"subname": "_acme-challenge",
			"type": "TXT",
			"ttl": 60,
			"records": ["\"token-aaaa\"", "\"token-bbbb\""],
		},
	]);
	let (provider, state) = mock(rrsets).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(
		!body.contains("token-aaaa"),
		"matching value still in body: {body}"
	);
	assert!(body.contains("token-bbbb"), "sibling value dropped: {body}");
}

/// Pull the first `"records":[...]` array out of a deSEC PUT body and
/// decode each element as a JSON string. The body is JSON, so this
/// avoids any hand-rolled parsing.
fn extract_records(body: &str) -> Vec<String> {
	let value: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
	let array = value.as_array().expect("top-level array");
	let rrset = array.first().expect("one rrset");
	let records = rrset
		.get("records")
		.and_then(|r| r.as_array())
		.expect("records");
	records
		.iter()
		.map(|v| v.as_str().expect("string record").to_string())
		.collect()
}

/// Mirror what a DNS resolver does on read: each record is a sequence
/// of one or more quoted character-strings; walk the pieces, drop the
/// surrounding double quotes on each, resolve the per-piece `\\` and
/// `\"` escapes, and concatenate in order. Works for the short-value
/// shape (one quoted string per record) and the long-value joined
/// shape (multiple quoted strings inside one record, separated by a
/// single space).
fn assemble_records(records: &[String]) -> String {
	let mut out = String::new();
	for record in records {
		let bytes = record.as_bytes();
		let mut i = 0;
		while i < bytes.len() {
			if bytes[i] == b'"' {
				let piece_start = i + 1;
				let mut piece_end = piece_start;
				while piece_end < bytes.len() {
					if bytes[piece_end] == b'\\' && piece_end + 1 < bytes.len() {
						piece_end += 2;
					} else if bytes[piece_end] == b'"' {
						break;
					} else {
						piece_end += 1;
					}
				}
				if piece_end >= bytes.len() {
					break;
				}
				let piece = &record[piece_start..piece_end];
				let mut chars = piece.chars();
				while let Some(c) = chars.next() {
					if c == '\\' {
						match chars.next() {
							Some('\\') => out.push('\\'),
							Some('"') => out.push('"'),
							Some(other) => {
								out.push('\\');
								out.push(other);
							}
							None => out.push('\\'),
						}
					} else {
						out.push(c);
					}
				}
				i = piece_end + 1;
			} else {
				i += 1;
			}
		}
	}
	out
}

/// Length of each quoted piece inside a joined deSEC `records`
/// entry. The wire form is `"piece1" "piece2"`; the pieces are the
/// substrings between the surrounding double quotes, with the
/// per-piece backslash/quote escapes honored so `\"` is one escaped
/// quote (2 wire bytes), not a piece terminator. Returns the
/// wire-byte lengths, in order, so the assertions compare against
/// `vec![255, 145]` without printing the underlying bytes.
fn record_piece_lengths(record: &str) -> Vec<usize> {
	let bytes = record.as_bytes();
	let mut out = Vec::new();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'"' {
			let start = i + 1;
			let mut j = start;
			while j < bytes.len() {
				if bytes[j] == b'\\' && j + 1 < bytes.len() {
					j += 2;
				} else if bytes[j] == b'"' {
					break;
				} else {
					j += 1;
				}
			}
			if j >= bytes.len() {
				break;
			}
			out.push(j - start);
			i = j + 1;
		} else {
			i += 1;
		}
	}
	out
}

/// The wire form of a deSEC `records` entry the production code
/// writes and reads back: each ≤255-octet character-string is
/// backslash/quote-escaped per piece, then wrapped in double quotes,
/// then the pieces are joined with single spaces. Used to seed the
/// mock with the same shape the production code writes, so the
/// value-bearing delete's needle matches the listed record.
fn records_joined_form(value: &str) -> String {
	let mut start = 0;
	let mut out = String::new();
	while start < value.len() {
		let mut end = (start + 255).min(value.len());
		while end < value.len() && !value.is_char_boundary(end) {
			end -= 1;
		}
		let piece = &value[start..end];
		let escaped = piece.replace('\\', "\\\\").replace('"', "\\\"");
		if !out.is_empty() {
			out.push(' ');
		}
		out.push('"');
		out.push_str(&escaped);
		out.push('"');
		start = end;
	}
	out
}

#[tokio::test]
async fn list_parses_rrsets_and_unquotes_txt() {
	let rrsets = serde_json::json!([
		{ "subname": "", "type": "TXT", "ttl": 3600, "records": ["\"v=spf1 -all\""] },
		{ "subname": "_dmarc", "type": "TXT", "ttl": 3600, "records": ["\"v=DMARC1; p=none\""] }
	]);
	let (provider, _state) = mock(rrsets).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(records.iter().any(|r| r.name == "_dmarc.example.org"));
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	assert!(state.lock().unwrap().puts.is_empty());
}

#[tokio::test]
async fn mx_upsert_passes_value_through_verbatim() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	// deSEC stores MX records as `<priority> <target>` in `records`.
	assert!(
		body.contains("\"records\":[\"10 mail.example.org\"]"),
		"{body}"
	);
}

#[tokio::test]
async fn srv_upsert_puts_unquoted_value_with_correct_subname() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org.".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"subname\":\"_submissions._tcp\""), "{body}");
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	// deSEC stores SRV values unquoted, as `<prio> <weight> <port> <target>`.
	assert!(
		body.contains("\"records\":[\"0 1 465 mail.example.org.\"]"),
		"{body}"
	);
}

#[tokio::test]
async fn caa_upsert_passes_value_through_verbatim() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let caa = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Caa,
		value: "0 issue \"letsencrypt.org\"".into(),
		ttl: 3600,
		proxied: None,
	};
	provider.upsert("example.org", caa).await.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	assert!(body.contains("\"subname\":\"\""), "{body}");
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	assert!(
		body.contains("\"records\":[\"0 issue \\\"letsencrypt.org\\\"\"]"),
		"{body}"
	);
}

/// deSEC RRsets have no description field, so the body carries exactly the
/// documented RRset fields and nothing epistle-specific.
#[tokio::test]
async fn upsert_body_has_only_the_documented_rrset_fields() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body: serde_json::Value = serde_json::from_str(&state.lock().unwrap().puts[0]).unwrap();
	let mut keys: Vec<&str> = body.as_array().expect("bulk array")[0]
		.as_object()
		.expect("object")
		.keys()
		.map(String::as_str)
		.collect();
	keys.sort_unstable();
	assert_eq!(keys, vec!["records", "subname", "ttl", "type"]);
}

mod txt_forms;

mod contract;

mod txt_long;
