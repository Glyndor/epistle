//! Tests for the domain normaliser.

use super::{DomainError, normalize};

#[test]
fn normalizes_a_u_label_to_its_a_label() {
	assert_eq!(
		normalize("Bücher.example").unwrap(),
		"xn--bcher-kva.example"
	);
}

#[test]
fn an_a_label_passes_through_lowercased() {
	assert_eq!(
		normalize("XN--BCHER-KVA.Example").unwrap(),
		"xn--bcher-kva.example"
	);
}

#[test]
fn ascii_names_pass_through_lowercased() {
	assert_eq!(normalize("Example.COM").unwrap(), "example.com");
}

#[test]
fn lowercasing_happens_after_punycode() {
	// Uppercase U-labels must encode (UTS 46 lowercases during processing)
	// before we lowercase the A-label. Encoding before lowercasing would
	// produce a different or invalid string.
	assert_eq!(
		normalize("BÜCHER.example").unwrap(),
		"xn--bcher-kva.example"
	);
}

#[test]
fn rejects_a_cyrillic_look_alike_of_a_latin_name() {
	// Cyrillic `р` (U+0440) and `а` (U+0430) make this look like `paypal`.
	assert_eq!(normalize("раypal.com"), Err(DomainError::Confusable));
}

#[test]
fn rejects_a_label_that_mixes_scripts() {
	// Only the second letter is Cyrillic, mixed-script per TR39.
	assert_eq!(normalize("pаypal.com"), Err(DomainError::Confusable));
}

#[test]
fn accepts_a_single_script_cyrillic_domain() {
	assert_eq!(normalize("пример.рф").unwrap(), "xn--e1afmkfd.xn--p1ai");
}

#[test]
fn accepts_japanese_kana_and_kanji_together() {
	let ascii = normalize("日本語ドメイン.jp").expect("single-script japanese");
	assert!(ascii.starts_with("xn--"), "{ascii}");
	assert!(ascii.ends_with(".jp"), "{ascii}");
	// Decoding back via the same library gives us the original U-label.
	let (back, _err) = idna::domain_to_unicode(&ascii);
	assert_eq!(back, "日本語ドメイン.jp");
}

#[test]
fn rejects_invalid_punycode() {
	assert_eq!(normalize("xn--.example"), Err(DomainError::Invalid));
	assert_eq!(
		normalize("xn--999999999999.example"),
		Err(DomainError::Invalid)
	);
}

#[test]
fn rejects_a_name_whose_a_label_exceeds_the_wire_cap() {
	// 60 Cyrillic chars UTF-8-encode to 120 octets (well under 253), but
	// each punycode-encodes to roughly its own width plus a few extra bytes
	// per new code point, so the resulting A-label is over the 63-octet
	// per-label cap that `idna::domain_to_ascii_strict` enforces.
	let label: String = "ы".repeat(60);
	let raw = format!("{label}.example.com");
	assert_eq!(normalize(&raw), Err(DomainError::Invalid));
}

#[test]
fn rejects_control_characters_and_empty() {
	assert_eq!(normalize(""), Err(DomainError::Invalid));
	assert_eq!(normalize("a\u{7}b.example"), Err(DomainError::Invalid));
}

#[test]
fn rejects_surrounding_whitespace() {
	assert_eq!(normalize(" example.org"), Err(DomainError::Invalid));
	assert_eq!(normalize("example.org "), Err(DomainError::Invalid));
}

#[test]
fn rejects_an_uppercase_a_label_with_a_leading_hyphen() {
	// STD3 hyphen rule: a label may not start or end with a hyphen in a
	// strict IDNA2008 conversion. Domain already in A-label form.
	assert_eq!(normalize("-foo.example"), Err(DomainError::Invalid));
	assert_eq!(normalize("foo-.example"), Err(DomainError::Invalid));
}

#[test]
fn rejects_a_domain_without_a_dot() {
	assert_eq!(normalize("example"), Err(DomainError::Invalid));
	assert_eq!(normalize("example."), Err(DomainError::Invalid));
}

#[test]
fn rejects_a_single_script_label_with_an_ascii_skeleton() {
	// Pure-Cyrillic `со` is single-script (mixed-script passes), but its
	// skeleton is the ASCII string `co`, so only the skeleton check
	// fires here. Deleting the skeleton check lets this through.
	assert_eq!(normalize("со.example"), Err(DomainError::Confusable));
}

#[test]
fn rejects_a_mixed_script_label_with_a_non_ascii_skeleton() {
	// Latin `hello` + CJK `中` is mixed-script (the mixed-script check
	// fires), but the skeleton still carries the CJK code point, so the
	// skeleton check skips it. Only the mixed-script check fires here.
	assert_eq!(normalize("hello中.example"), Err(DomainError::Confusable));
}
