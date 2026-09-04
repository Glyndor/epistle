//! Tests for URL host extraction.

use super::*;

#[test]
fn finds_http_and_https_hosts() {
	let body = b"visit https://example.com/path or http://foo.bar.example for more";
	let hosts = extract_hosts(body, DEFAULT_HOST_CAP);
	assert_eq!(
		hosts,
		vec!["example.com".to_string(), "foo.bar.example".to_string()]
	);
}

#[test]
fn decodes_quoted_printable_soft_breaks_and_3d() {
	// A QP soft break INSIDE the host label must be unfolded so the host is
	// reconstructed; =3D decoding lets an equals sign appear in URL context
	// without breaking the scan.
	let body = b"see https://ex=\r\nample.com/?q=3D1 and http://oth=\r\ner.example/path";
	let hosts = extract_hosts(body, DEFAULT_HOST_CAP);
	assert_eq!(
		hosts,
		vec!["example.com".to_string(), "other.example".to_string()]
	);
}

#[test]
fn caps_and_dedupes() {
	// a appears twice and the cap is 3; dedup must collapse the duplicate so
	// the result has a.example, b.example, c.example, and the cap then stops
	// further pushes.
	let body =
		b"http://a.example http://b.example http://a.example http://c.example http://d.example";
	let hosts = extract_hosts(body, 3);
	assert_eq!(
		hosts,
		vec![
			"a.example".to_string(),
			"b.example".to_string(),
			"c.example".to_string(),
		]
	);
}

#[test]
fn ignores_ip_literals_and_localhost() {
	let body = b"links: http://127.0.0.1/x http://[::1]/y http://localhost/z http://real.example/p";
	let hosts = extract_hosts(body, DEFAULT_HOST_CAP);
	assert_eq!(hosts, vec!["real.example".to_string()]);
}

#[test]
fn stops_at_256_kib() {
	// 300 KiB of padding with a real URL only after the 256 KiB boundary:
	// the real URL must NOT be returned.
	let pad = vec![b'x'; 300 * 1024];
	let mut body = pad.clone();
	body.extend_from_slice(b"http://late.example/path");
	let hosts = extract_hosts(&body, DEFAULT_HOST_CAP);
	assert!(
		hosts.is_empty(),
		"URL past the 256 KiB boundary must be ignored, got {hosts:?}"
	);
}

#[test]
fn url_inside_first_256kib_is_kept() {
	let pad = vec![b'x'; 200 * 1024];
	let mut body = pad;
	body.extend_from_slice(b"http://early.example/path");
	let hosts = extract_hosts(&body, DEFAULT_HOST_CAP);
	assert_eq!(hosts, vec!["early.example".to_string()]);
}
