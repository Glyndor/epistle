use super::*;

#[test]
fn the_three_shapes_parse_to_what_they_name() {
	assert_eq!(
		Entry::parse(" Alice@Example.COM "),
		Ok(Entry::Address("alice@example.com".into()))
	);
	assert_eq!(
		Entry::parse("Example.com"),
		Ok(Entry::Domain("example.com".into()))
	);
	assert_eq!(
		Entry::parse("*.example.com"),
		Ok(Entry::Subdomains("example.com".into()))
	);
}

#[test]
fn malformed_entries_are_refused_with_a_reason() {
	for bad in [
		"",
		"   ",
		"*",
		"*.",
		"*.com",
		"a*.example.com",
		"example.*",
		"@example.com",
		"user@",
		"user@example",
		"a b@example.com",
		"two@@example.com",
		"-bad.example.com",
		"exa mple.com",
		"localhost",
		"*.example.com.*",
	] {
		assert!(Entry::parse(bad).is_err(), "{bad:?} must be refused");
	}
	let long = format!("{}@example.com", "a".repeat(400));
	assert!(Entry::parse(&long).is_err());
}
