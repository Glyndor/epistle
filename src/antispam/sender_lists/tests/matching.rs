use super::*;

fn matcher(entries: &[&str]) -> Matcher {
	Matcher::new(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>())
}

#[test]
fn an_address_entry_matches_that_address_only() {
	let list = matcher(&["alice@example.com"]);
	assert!(list.matches("alice@example.com"));
	assert!(list.matches("ALICE@Example.Com"));
	assert!(!list.matches("bob@example.com"));
	assert!(!list.matches("alice@mail.example.com"));
}

#[test]
fn a_domain_entry_matches_the_domain_and_not_its_subdomains() {
	let list = matcher(&["example.com"]);
	assert!(list.matches("anyone@example.com"));
	assert!(list.matches("anyone@example.com."));
	assert!(!list.matches("anyone@mail.example.com"));
}

#[test]
fn a_wildcard_matches_subdomains_at_any_depth_and_not_the_apex() {
	let list = matcher(&["*.example.com"]);
	assert!(list.matches("a@mail.example.com"));
	assert!(list.matches("a@deep.mail.example.com"));
	assert!(
		!list.matches("a@example.com"),
		"the apex is not a subdomain"
	);
}

#[test]
fn near_misses_of_a_wildcard_do_not_match() {
	let list = matcher(&["*.example.com", "example.com"]);
	assert!(!list.matches("a@badexample.com"));
	assert!(!list.matches("a@example.com.example.net"));
	assert!(!list.matches("a@xexample.com"));
	assert!(!list.matches("example.com"), "no domain part, no match");
}

#[test]
fn the_null_reverse_path_and_a_bare_word_never_match() {
	let list = matcher(&["example.com", "*.example.com", "a@example.com"]);
	assert!(!list.matches(""));
	assert!(!list.matches("<>"));
	assert!(!list.matches("example.com"));
}

#[test]
fn an_empty_list_matches_nothing() {
	let list = matcher(&[]);
	assert!(list.is_empty());
	assert!(!list.matches("a@example.com"));
}

#[test]
fn the_domain_after_the_last_at_sign_decides() {
	let list = matcher(&["example.com"]);
	assert!(list.matches("\"a@example.net\"@example.com"));
	assert!(!list.matches("\"a@example.com\"@example.net"));
}

#[test]
fn spellings_of_one_address_are_one_address_to_the_lists() {
	let list = matcher(&["Bad@Example.COM", "*.spam.example.net", "bücher.example"]);
	for variant in [
		"bad@example.com",
		"BAD@EXAMPLE.COM",
		"<bad@example.com>",
		" bad@example.com ",
		"\"bad\"@example.com",
		"bad@example.com.",
		"a@x.SPAM.example.net",
		"a@x.spam.example.net.",
		"a@Bücher.example",
		"a@xn--bcher-kva.example",
		"a@XN--BCHER-KVA.example.",
	] {
		assert!(list.matches(variant), "{variant:?} must match");
	}
	// The control: a different address of the same domains does not.
	for other in ["good@example.com", "a@spam.example.net", "a@bucher.example"] {
		assert!(!list.matches(other), "{other:?} must not match");
	}
}

#[test]
fn an_entry_written_in_unicode_and_one_in_punycode_are_the_same_entry() {
	let unicode = matcher(&["*.bücher.example"]);
	let ascii = matcher(&["*.xn--bcher-kva.example"]);
	for address in ["a@x.bücher.example", "a@x.xn--bcher-kva.example"] {
		assert!(
			unicode.matches(address) && ascii.matches(address),
			"{address}"
		);
	}
}
