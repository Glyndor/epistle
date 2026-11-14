//! Tests for the one mailbox that may go into a header as it is.

use super::*;

#[test]
fn a_plain_mailbox_is_split_into_local_part_and_domain() {
	assert_eq!(
		plain_mailbox("dmarc@example.org"),
		Some(("dmarc", "example.org"))
	);
	assert_eq!(
		plain_mailbox("dmarc+reports.2024@mail.example.org"),
		Some(("dmarc+reports.2024", "mail.example.org"))
	);
}

#[test]
fn anything_that_could_leave_the_header_or_name_a_second_address_is_refused() {
	for bad in [
		"",
		"dmarc",
		"@example.org",
		"dmarc@",
		"a b@example.org",
		"a\tb@example.org",
		"a@example.org, b@example.net",
		"a@example.org,b@example.net",
		"a@example.org;b@example.net",
		"a@b@example.org",
		"a@example.org\r\nBcc: x@example.org",
		"a@example.org\nBcc: x@example.org",
		"a@example.org\r",
		"\"a b\"@example.org",
		"a@[127.0.0.1]",
		"Dmarc <dmarc@example.org>",
		"<dmarc@example.org>",
		"dmarc@example.org (reports)",
		"dmarc@exämple.org",
		"dmarc@example.org\0",
	] {
		assert_eq!(plain_mailbox(bad), None, "{bad:?} must be refused");
	}
}

#[test]
fn the_mailbox_stops_at_254_bytes() {
	let domain = "example.org";
	let longest = format!("{}@{domain}", "a".repeat(254 - 1 - domain.len()));
	assert_eq!(longest.len(), 254);
	assert!(plain_mailbox(&longest).is_some());
	let too_long = format!("a{longest}");
	assert_eq!(plain_mailbox(&too_long), None);
}
