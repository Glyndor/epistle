//! The names a record may be written at, and the short form of a name too
//! long to print.

use super::*;

#[test]
fn only_letters_digits_hyphens_and_underscores_are_written_at() {
	assert!(is_valid_name("www.example.org"));
	assert!(is_valid_name("_dmarc.example.org"));
	assert!(is_valid_name("*.example.org"));
	assert!(!is_valid_name(""));
	assert!(!is_valid_name("sp ace.example.org"));
	assert!(!is_valid_name("nul\0.example.org"));
	assert!(!is_valid_name("ev\u{1b}[2Jil.example.org"));
	assert!(!is_valid_name("bücher.example.org"));
}

#[test]
fn a_label_longer_than_the_dns_limit_is_not_written_at() {
	let too_long = format!("{}.example.org", "a".repeat(MAX_LABEL_LEN + 1));
	assert!(!is_valid_name(&too_long));
	let at_the_limit = format!("{}.example.org", "a".repeat(MAX_LABEL_LEN));
	assert!(is_valid_name(&at_the_limit));
}

#[test]
fn a_name_too_long_to_print_is_cut_down() {
	assert_eq!(shortened("example.org"), "example.org");
	assert_eq!(
		shortened(&"é".repeat(300)).len(),
		252 + 3,
		"cut on a character boundary"
	);
}
