use super::*;

#[test]
fn relaxed_header_lowercases_and_collapses() {
	assert_eq!(
		header(Canon::Relaxed, "Subject", "  Hello \t world\r\n\t!"),
		"subject:Hello world !\r\n"
	);
}

#[test]
fn simple_header_is_verbatim() {
	assert_eq!(
		header(Canon::Simple, "Subject", " Hello"),
		"Subject: Hello\r\n"
	);
}

#[test]
fn relaxed_body_collapses_and_trims() {
	let input = b"Hello \t world \r\nline2\t\tx\r\n\r\n\r\n";
	assert_eq!(body(Canon::Relaxed, input), b"Hello world\r\nline2 x\r\n");
}

#[test]
fn simple_body_strips_trailing_blank_lines_only() {
	let input = b"Hello  world\r\n\r\n\r\n";
	assert_eq!(body(Canon::Simple, input), b"Hello  world\r\n");
}

#[test]
fn empty_bodies() {
	assert_eq!(body(Canon::Simple, b""), b"\r\n");
	assert_eq!(body(Canon::Relaxed, b""), b"");
}
