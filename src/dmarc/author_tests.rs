use super::*;

#[test]
fn reads_the_single_from_field() {
	assert_eq!(
		author(b"Subject: x\r\nFrom: \"Alice\" <alice@example.org>\r\n\r\nFrom: not@header.example\r\n"),
		Author::Addresses(vec!["alice@example.org".to_string()])
	);
	assert_eq!(
		author(b"from:\r\n <carol@example.org>\r\n\r\n"),
		Author::Addresses(vec!["carol@example.org".to_string()])
	);
}

#[test]
fn counts_every_spelling_of_the_from_name() {
	for raw in [
		&b"From: a@x.example\r\nFROM: b@x.example\r\n\r\n"[..],
		b"From: a@x.example\r\nFrom\t: b@x.example\r\n\r\n",
		b"From : a@x.example\r\nfrom: a@x.example\r\n\r\n",
	] {
		assert_eq!(author(raw), Author::MultipleFields);
	}
}

#[test]
fn a_field_without_an_address_is_missing() {
	assert_eq!(author(b"Subject: x\r\n\r\n"), Author::Missing);
	assert_eq!(author(b"From: undisclosed:;\r\n\r\n"), Author::Missing);
	assert_eq!(author(b"From: \xff@x.example\r\n\r\n"), Author::Missing);
}

#[test]
fn groups_and_lists_yield_every_address() {
	assert_eq!(
		author(b"From: team: a@x.example, b@y.example;\r\n\r\n"),
		Author::Addresses(vec!["a@x.example".to_string(), "b@y.example".to_string()])
	);
	assert_eq!(
		author_domain(b"From: team: a@x.example, b@y.example;\r\n\r\n"),
		AuthorDomain::Multiple
	);
}

#[test]
fn a_domain_that_cannot_be_a_dns_name_is_missing() {
	assert_eq!(author_domain(b"From: a@\r\n\r\n"), AuthorDomain::Missing);
	assert_eq!(
		author_domain(b"From: \"a@x\" <@>\r\n\r\n"),
		AuthorDomain::Missing
	);
}
