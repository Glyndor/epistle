use super::{address_key, date_header_seconds};

#[test]
fn the_address_key_is_the_first_mailbox() {
	let key = |value: &str| address_key(&format!("From: {value}\r\n\r\nx\r\n"), "from");
	assert_eq!(key("Foo Bar <user2@domain2.org>, a@b.org"), "USER2");
	assert_eq!(key("user2@domain2.org (foo bar)"), "USER2");
	assert_eq!(key("user2: blah@domain1.org;"), "USER2");
	assert_eq!(key("<@route.org:local@host.org>"), "LOCAL");
	assert_eq!(address_key("Subject: x\r\n\r\n", "from"), "");
}

#[test]
fn the_date_header_is_read_in_utc() {
	let message = "Date: Fri, 22 Feb 2008 10:00:00 +0500\r\n\r\nx\r\n";
	// 2008-02-22T05:00:00Z.
	assert_eq!(date_header_seconds(message), Some(1_203_656_400));
	assert_eq!(date_header_seconds("Date: someday\r\n\r\n"), None);
	assert_eq!(date_header_seconds("Subject: x\r\n\r\n"), None);
}
