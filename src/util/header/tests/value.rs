use super::header_value;

#[test]
fn unfolds_first_header_without_reading_other_fields_or_body() {
	for newline in ["\r\n", "\n"] {
		let raw = [
			"X-Note: other",
			" subject: continuation of X-Note",
			"sUbJeCt: First",
			" second",
			"\tthird",
			"Subject: duplicate",
			"",
			"Subject: body",
			"Bcc: body@example.org",
		]
		.join(newline);
		assert_eq!(
			header_value(&raw, "SUBJECT").as_deref(),
			Some("First second third")
		);
		assert_eq!(header_value(&raw, "bcc"), None);
	}
}
