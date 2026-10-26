use super::*;

#[test]
fn submission_headers_keep_the_clients_line_ending_style() {
	let data = b"From: alice@example.org\nSubject: hi\n\nbody\n";
	let stamped = ensure_submission_headers(data, "example.org", SystemTime::now());
	assert!(
		!stamped.contains(&b'\r'),
		"the stamp mixed CRLF into an LF message"
	);
	assert!(stamped.ends_with(b"body\n"), "the body changed");
}

#[test]
fn prepended_headers_keep_the_clients_line_ending_style() {
	for (raw, body) in [
		(
			b"From: alice@example.org\nSubject: hi\n\nbody\n".as_slice(),
			b"body\n".as_slice(),
		),
		(
			b"\nX-Epistle: body\n".as_slice(),
			b"X-Epistle: body\n".as_slice(),
		),
	] {
		for stamp in [false, true] {
			let mut data = raw.to_vec();
			if stamp {
				ensure_submission_headers_in_place(
					&mut data,
					"example.org",
					SystemTime::UNIX_EPOCH,
				);
				assert!(data.starts_with(b"Message-ID:"));
				assert!(String::from_utf8_lossy(&data).contains("Date:"));
			} else {
				prepend_header_block(&mut data, "Feedback-ID: test\r\n");
				assert!(data.starts_with(b"Feedback-ID: test\n"));
			}
			assert!(
				!data.contains(&b'\r'),
				"I expect LF throughout the stamped message"
			);
			let boundary = data
				.windows(2)
				.position(|w| w == b"\n\n")
				.expect("header boundary");
			assert_eq!(&data[boundary + 2..], body);
		}
	}
}

#[test]
fn a_leading_blank_line_ends_the_header_block() {
	let data = b"\r\nX-Epistle: forged\r\nbody\r\n";
	let stripped = strip_headers_with_namespace(data, "X-Epistle");
	assert_eq!(stripped, data, "a body line was read as a header");
}
