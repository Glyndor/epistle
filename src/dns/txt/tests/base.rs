//! Tests for the shared TXT encoding.

use super::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, SPECIAL_PRESENTATION, dkim_rsa2048,
	dkim_rsa2048_presentation,
};
use super::*;

#[test]
fn a_logical_value_reads_back_unchanged() {
	assert_eq!(txt_logical(SHORT), SHORT);
	assert_eq!(txt_logical(SPECIAL), SPECIAL);
	assert_eq!(txt_logical(&dkim_rsa2048()), dkim_rsa2048());
	assert_eq!(txt_logical("  token-aaaa \n"), "token-aaaa");
}

#[test]
fn one_quoted_string_loses_its_quotes() {
	assert_eq!(txt_logical(CALLER_QUOTED), CALLER_QUOTED_LOGICAL);
	assert_eq!(txt_logical("\"\""), "");
}

#[test]
fn several_quoted_strings_join_with_nothing_between() {
	assert_eq!(txt_logical(&dkim_rsa2048_presentation()), dkim_rsa2048());
	assert_eq!(txt_logical("\"ab\"\"cd\""), "abcd");
	assert_eq!(txt_logical("\"ab\"   \"cd\""), "abcd");
}

#[test]
fn escapes_are_resolved() {
	assert_eq!(txt_logical(SPECIAL_PRESENTATION), SPECIAL);
	assert_eq!(txt_logical(r#""a\059b""#), "a;b");
	assert_eq!(txt_logical(r#""a\ b""#), "a b");
}

/// Text that is not a clean run of quoted strings is taken as logical, so a
/// value that only happens to start with a quote is not mangled.
#[test]
fn a_value_that_is_not_presentation_form_is_left_alone() {
	assert_eq!(txt_logical("\"open"), "\"open");
	assert_eq!(txt_logical("\"a\" b"), "\"a\" b");
	assert_eq!(txt_logical(r#""a\25""#), r#""a\25""#);
	assert_eq!(txt_logical(r#""a\999""#), r#""a\999""#);
}

#[test]
fn a_long_value_splits_at_255_octets() {
	let parts = txt_character_strings(&dkim_rsa2048());
	assert_eq!(parts.len(), 2);
	assert_eq!(parts[0].len(), 255);
	assert_eq!(parts.concat(), dkim_rsa2048());
}

#[test]
fn character_strings_read_the_logical_value_first() {
	let quoted = format!("\"{}\"", dkim_rsa2048());
	assert_eq!(
		txt_character_strings(&quoted),
		txt_character_strings(&dkim_rsa2048())
	);
	assert_eq!(
		txt_character_strings(CALLER_QUOTED),
		vec![CALLER_QUOTED_LOGICAL.to_string()]
	);
}

#[test]
fn presentation_quotes_escapes_and_splits() {
	assert_eq!(txt_presentation(SHORT), format!("\"{SHORT}\""));
	assert_eq!(txt_presentation(SPECIAL), SPECIAL_PRESENTATION);
	assert_eq!(
		txt_presentation(&dkim_rsa2048()),
		dkim_rsa2048_presentation()
	);
}

/// The 255-octet cut counts logical octets: a piece full of quotes is still
/// 255 characters of text, and its escapes stay inside it. The value starts
/// with a letter because a value made only of quote characters reads as a
/// run of empty quoted strings, the one shape `txt_logical` cannot tell
/// from presentation form.
#[test]
fn the_cut_comes_before_the_escaping() {
	let value = format!("a{}", "\"".repeat(299));
	let rendered = txt_presentation(&value);
	assert_eq!(txt_logical(&rendered), value);
	let first = rendered.split(' ').next().unwrap();
	assert_eq!(first.len(), 2 + 1 + 254 * 2);
}

/// Encoding an already encoded value gives the same bytes again: a caller
/// that quoted its value, or a value read back from a provider and written
/// again, never ends up with doubled quotes.
#[test]
fn encoding_is_idempotent() {
	for (value, logical) in super::fixtures::all() {
		for form in [
			TxtForm::Logical,
			TxtForm::Presentation,
			TxtForm::PresentationOctal,
		] {
			let once = txt_encode(&value, form);
			assert_eq!(
				txt_encode(&txt_decode(&once, form), form),
				once,
				"{form:?} of {value}"
			);
			assert_eq!(txt_decode(&once, form), logical, "{form:?} of {value}");
		}
	}
}

#[test]
fn same_txt_value_ignores_the_shape() {
	assert!(same_txt_value(CALLER_QUOTED, CALLER_QUOTED_LOGICAL));
	assert!(same_txt_value(
		&dkim_rsa2048_presentation(),
		&dkim_rsa2048()
	));
	assert!(same_txt_value(SPECIAL_PRESENTATION, SPECIAL));
	assert!(!same_txt_value(SHORT, "v=spf1 -all"));
}

/// An octet outside printable ASCII is a numeric escape: decimal for RFC
/// 1035, octal for Route 53. Each reads back with its own radix.
#[test]
fn numeric_escapes_follow_the_form() {
	assert_eq!(txt_presentation("café"), r#""caf\195\169""#);
	assert_eq!(
		txt_encode("café", TxtForm::PresentationOctal),
		r#""caf\303\251""#
	);
	assert_eq!(txt_logical(r#""caf\195\169""#), "café");
	assert_eq!(
		txt_decode(r#""caf\303\251""#, TxtForm::PresentationOctal),
		"café"
	);
	assert_eq!(
		txt_decode(r#""a\9""#, TxtForm::PresentationOctal),
		r#""a\9""#
	);
}
