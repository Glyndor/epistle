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

/// Craft the input the issue names: a body of `http://a.b/ ` repeated
/// until the scan window is full. Each token is 12 bytes, so the window
/// holds exactly `MAX_SCAN_BYTES / 12` URLs (the trailing space keeps
/// the next URL at a fresh position).
fn crafted_body(size: usize) -> Vec<u8> {
	let token = b"http://a.b/ ";
	let mut body = Vec::with_capacity(size);
	while body.len() + token.len() <= size {
		body.extend_from_slice(token);
	}
	body
}

#[test]
fn scan_step_count_grows_at_most_linearly_on_the_crafted_input() {
	// Regression for #968: a body of repeated URLs must not push the per
	// call work past linear. The old `find_subslice(rest, b"http://")`
	// loop re-scanned the remaining suffix on every iteration, so the
	// step counter grew quadratically with the number of URLs in the
	// window. The forward scan touches each byte position once.
	//
	// The body the issue names is `http://a.b/ ` repeated, which is one
	// unique host. With the default cap (50) the scan stops after the
	// first match, so the step counter would be tiny and would not
	// exercise the work the issue is about. Use a cap larger than the
	// number of unique hosts in the body so the scan walks the full
	// window; the cap is still honoured because distinct hosts in the
	// body are bounded by the body size.
	let body = crafted_body(MAX_SCAN_BYTES);
	let scan_cap = body.len();
	reset_scan_steps();
	let hosts = extract_hosts(&body, scan_cap);
	let steps = reset_scan_steps();
	assert_eq!(hosts.len(), 1, "dedup keeps exactly one host, got {hosts:?}");
	assert_eq!(hosts[0], "a.b");
	// Linear bound: the forward scan advances at least one byte per
	// iteration and at most `7 + host_length` bytes per scheme match,
	// so the step count must sit at most a small constant times the
	// body size. The old quadratic implementation ran ~body.len()^2 /
	// 12 comparisons on this crafted input, which the upper bound
	// catches decisively.
	let body_len = body.len() as u64;
	assert!(
		steps <= body_len * 2,
		"forward scan should stay within a small constant of the body size, got {steps} for {body_len} bytes"
	);
}

#[test]
fn doubling_the_crafted_input_at_most_doubles_the_step_count() {
	// The linearity check from the issue: feeding twice the crafted
	// input must at most roughly double the step count, with a fixed
	// slack for the per-call overhead that does not depend on the
	// input size. The old quadratic scan broke this with a 4x ratio
	// for a 2x input.
	//
	// Use the repeated-URL body the issue names (`http://a.b/ `
	// packed to the scan window) so every `find_subslice(rest, ...)`
	// call scans the remaining suffix to the end. A body of distinct
	// hosts would let the quadratic implementation look linear because
	// each per-iteration scan finds a match just past the cursor.
	let small = crafted_body(MAX_SCAN_BYTES / 2);
	let large = crafted_body(MAX_SCAN_BYTES);
	// Cap larger than the number of unique hosts (1) so the scan walks
	// the full window; the dedup is what stops the result list, not
	// the cap.
	let scan_cap = small.len() + large.len();
	reset_scan_steps();
	extract_hosts(&small, scan_cap);
	let small_steps = reset_scan_steps();
	reset_scan_steps();
	extract_hosts(&large, scan_cap);
	let large_steps = reset_scan_steps();
	// linear: count(2N) <= 2 * count(N) + slack
	assert!(
		large_steps as u128 <= small_steps as u128 * 2 + 4096,
		"step count grew superlinearly: small={small_steps}, large={large_steps}"
	);
}

