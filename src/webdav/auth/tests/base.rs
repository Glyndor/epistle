use super::*;
use axum::http::HeaderValue;

/// Standard base64 encode for building test Authorization headers.
fn base64_encode(input: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::new();
	for chunk in input.chunks(3) {
		let b = [
			chunk[0],
			*chunk.get(1).unwrap_or(&0),
			*chunk.get(2).unwrap_or(&0),
		];
		let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
		out.push(ALPHABET[(n >> 18) as usize & 63] as char);
		out.push(ALPHABET[(n >> 12) as usize & 63] as char);
		out.push(if chunk.len() > 1 {
			ALPHABET[(n >> 6) as usize & 63] as char
		} else {
			'='
		});
		out.push(if chunk.len() > 2 {
			ALPHABET[n as usize & 63] as char
		} else {
			'='
		});
	}
	out
}

fn header(value: &str) -> HeaderMap {
	let mut map = HeaderMap::new();
	map.insert(AUTHORIZATION, HeaderValue::from_str(value).expect("header"));
	map
}

#[test]
fn parses_basic_credentials() {
	let encoded = base64_encode(b"alice:secret");
	let map = header(&format!("Basic {encoded}"));
	let (login, password) = basic_credentials(&map).expect("creds");
	assert_eq!(login, "alice");
	// `assert_eq!` on `password` would Debug-print the actual
	// password on a mismatch, dumping the credential into the
	// CI log. The boolean form names the contract without
	// echoing the payload.
	assert!(
		password == "secret",
		"the Basic password must round-trip the header"
	);
}

#[test]
fn password_may_contain_colon() {
	let encoded = base64_encode(b"alice:a:b:c");
	let map = header(&format!("Basic {encoded}"));
	let (login, password) = basic_credentials(&map).expect("creds");
	assert_eq!(login, "alice");
	// `assert_eq!` on `password` would Debug-print the actual
	// password on a mismatch, dumping the credential into the
	// CI log. The boolean form names the contract without
	// echoing the payload.
	assert!(
		password == "a:b:c",
		"the Basic password must round-trip colons verbatim"
	);
}

#[test]
fn rejects_missing_header() {
	assert!(basic_credentials(&HeaderMap::new()).is_none());
}

#[test]
fn rejects_non_basic_scheme() {
	let map = header("Bearer token");
	assert!(basic_credentials(&map).is_none());
}

#[test]
fn rejects_missing_colon() {
	let encoded = base64_encode(b"alicesecret");
	let map = header(&format!("Basic {encoded}"));
	assert!(basic_credentials(&map).is_none());
}

#[test]
fn base64_decode_roundtrip() {
	for sample in ["", "a", "ab", "abc", "abcd", "user:pass", "a:b:c:d"] {
		let encoded = base64_encode(sample.as_bytes());
		assert_eq!(base64_decode(&encoded), Some(sample.as_bytes().to_vec()));
	}
}

#[test]
fn base64_decode_rejects_invalid_char() {
	assert!(base64_decode("!!!!").is_none());
}

fn basic(login: &str, password: &str) -> HeaderMap {
	header(&format!(
		"Basic {}",
		base64_encode(format!("{login}:{password}").as_bytes())
	))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_basic_logins_are_counted_against_the_client_address() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::smtp::directory::gate_fixture::{OPEN, gate_directory};
	use crate::test_fixtures as fixtures;

	let store = FakeBanStore::new(BanPolicy::default());
	let handle =
		DirectoryHandle::new(gate_directory().with_ban_store(std::sync::Arc::new(store.clone())));
	let guesser: Option<std::net::IpAddr> = Some("203.0.113.5".parse().expect("address"));
	let owner: Option<std::net::IpAddr> = Some("198.51.100.9".parse().expect("address"));
	for _ in 0..5 {
		assert_eq!(
			authenticate(&basic(OPEN, fixtures::wrong_password()), &handle, guesser),
			None
		);
	}
	assert_eq!(
		store.failure_count("ip:203.0.113.5", 0),
		5,
		"the failures were attributed to the client"
	);
	assert_eq!(
		authenticate(&basic(OPEN, fixtures::password()), &handle, guesser),
		None,
		"the guessing client is banned"
	);
	assert_eq!(
		authenticate(&basic(OPEN, fixtures::password()), &handle, owner),
		Some(OPEN.to_string()),
		"the owner, from elsewhere, is not"
	);
}
