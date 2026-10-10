use super::*;

fn report_body(payload: &str, ending: &str) -> Option<Vec<u8>> {
	let raw = format!(
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/tlsrpt+json\r\n\r\n{payload}\r\n{ending}"
	);
	find_report_part(raw.as_bytes(), Kind::TlsRpt)
		.ok()
		.map(|part| part.bytes)
}

#[test]
fn delimiter_prefix_lines_preserve_complete_payload() {
	for payload in ["{}\r\n--b-extra\r\n{}", "{}\r\n--b--extra\r\n{}"] {
		assert!(
			report_body(payload, "--b--\r\n").as_deref() == Some(payload.as_bytes()),
			"boundary prefixes must preserve the complete attachment byte count and contents"
		);
	}
}

#[test]
fn inline_boundary_text_preserves_json() {
	let payload = r#"{"organization-name":"org--b"}"#;
	assert!(
		report_body(payload, "--b--\r\n").as_deref() == Some(payload.as_bytes()),
		"inline boundary text must preserve the complete JSON payload"
	);
}

#[test]
fn delimiter_transport_padding_is_accepted() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b \t\r\nContent-Type: application/tlsrpt+json\r\n\r\n{}\r\n--b-- \t\r\n";
	let found = find_report_part(raw, Kind::TlsRpt).ok();
	assert!(
		found.map(|part| part.bytes).as_deref() == Some(b"{}"),
		"delimiter transport padding must preserve the complete report payload"
	);
}
