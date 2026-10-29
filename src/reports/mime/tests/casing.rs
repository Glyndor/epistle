use super::*;

fn decoded(raw: &str) -> Option<Vec<u8>> {
	find_report_part(raw.as_bytes(), Kind::TlsRpt)
		.ok()
		.map(|part| part.bytes)
}

#[test]
fn uppercase_boundary_parameter_preserves_payload() {
	let raw = "Content-Type: Multipart/Mixed; BOUNDARY=\"B\"\r\n\r\n--B\r\nContent-Type: Application/TlsRpt+Json\r\n\r\n{}\r\n--B--\r\n";
	assert!(
		decoded(raw).as_deref() == Some(b"{}"),
		"uppercase boundary parameter must decode the complete report payload"
	);
}

#[test]
fn mixed_case_nested_multipart_preserves_payload() {
	let raw = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: Multipart/Mixed; boundary=Inner\r\n\r\n--Inner\r\nContent-Type: Application/TlsRpt+Json\r\n\r\n{}\r\n--Inner--\r\n--outer--\r\n";
	assert!(
		decoded(raw).as_deref() == Some(b"{}"),
		"mixed-case nested multipart must decode the complete report payload"
	);
}

#[test]
fn uppercase_filename_parameter_preserves_payload() {
	let raw = "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; FILENAME=report.json\r\n\r\n{}";
	assert!(
		decoded(raw).as_deref() == Some(b"{}"),
		"uppercase filename parameter must decode the complete report payload"
	);
}
