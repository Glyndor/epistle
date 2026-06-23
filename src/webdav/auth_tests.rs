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
	assert_eq!(password, "secret");
}

#[test]
fn password_may_contain_colon() {
	let encoded = base64_encode(b"alice:a:b:c");
	let map = header(&format!("Basic {encoded}"));
	let (login, password) = basic_credentials(&map).expect("creds");
	assert_eq!(login, "alice");
	assert_eq!(password, "a:b:c");
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
