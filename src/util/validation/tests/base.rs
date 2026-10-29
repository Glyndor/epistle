use super::*;

/// Every character of RFC 5321 `atext` outside `ALPHA` and `DIGIT`, and only
/// those: a set written here by hand would drift from the one the RFC names,
/// which is the whole reason this file exists.
#[test]
fn atext_is_exactly_the_rfc_set() {
	let expected = "!#$%&'*+-/=?^_`{|}~";
	assert_eq!(ATEXT, expected);
	assert_eq!(ATEXT.chars().count(), 19, "nineteen specials");
	assert!(!ATEXT.contains('.'), "the dot separates atoms");
	assert!(
		ATEXT
			.bytes()
			.all(|b| b.is_ascii() && !b.is_ascii_alphanumeric()),
		"every member is ASCII punctuation"
	);
	assert_eq!(
		ATEXT
			.chars()
			.collect::<std::collections::BTreeSet<_>>()
			.len(),
		ATEXT.chars().count(),
		"no character appears twice"
	);
}

#[test]
fn atext_covers_alphanumeric_and_the_set_and_nothing_else() {
	for c in ATEXT.chars() {
		assert!(is_atext(c), "{c:?} is in the set");
		assert!(is_atext_byte(c as u8), "{c:?} is in the set as a byte");
	}
	for c in "azAZ09".chars() {
		assert!(
			is_atext(c) && is_atext_byte(c as u8),
			"{c:?} is alphanumeric"
		);
	}
	for c in ".()<>[]:;@\\,\"\r\n\t\0\u{7f} ".chars() {
		assert!(!is_atext(c), "{c:?} must not be accepted");
		assert!(!is_atext_byte(c as u8), "{c:?} must not be accepted");
	}
}

/// RFC 6531: the same rule over `char` admits a non-ASCII local part, and a
/// control character never sneaks in with it.
#[test]
fn smtputf8_local_parts_are_at_ext_plus_non_ascii() {
	assert!(is_atext('ä'), "U+00E4");
	assert!(is_atext('用'), "CJK");
	assert!(!is_atext('\r'));
	assert!(!is_atext('\n'));
	assert!(!is_atext('\0'));
	assert!(!is_atext('\u{7f}'), "DEL is a control character");
	// `char::is_control` is the C0 and C1 ranges only, so the Unicode line and
	// paragraph separators need their own refusal: they break a log line and
	// some clients the way a newline does, and the Sieve script-name and
	// mailbox-folder rules refuse them too.
	assert!(!is_atext('\u{2028}'), "line separator");
	assert!(!is_atext('\u{2029}'), "paragraph separator");
	assert!(is_atext('\u{2027}'), "the code point before the separators");
	assert!(
		is_atext('\u{202a}'),
		"the code point after them stays a character"
	);
}

#[test]
fn the_bidi_set_is_the_documented_one() {
	for c in [
		'\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}',
	] {
		assert!(is_bidi_or_invisible(c), "{c:?} must be refused in a name");
	}
	for c in ['a', '-', '.', '\u{2028}', '\u{00e4}', '\u{200b}'] {
		assert!(!is_bidi_or_invisible(c), "{c:?} is not a bidi control");
	}
}

#[test]
fn memory_sizes_follow_the_compose_shape() {
	assert_eq!(parse_memory_size("4g"), Some(4 * 1024 * 1024 * 1024));
	assert_eq!(parse_memory_size("512M"), Some(512 * 1024 * 1024));
	assert_eq!(parse_memory_size("64k"), Some(64 * 1024));
	// Zero is not a limit, so a value that resolves to zero is refused rather
	// than accepted as an empty cap.
	for value in ["0k", "0", "00m", "0G"] {
		assert_eq!(parse_memory_size(value), None, "{value}");
	}
	for value in [
		"",
		"k",
		"4t",
		"4g4",
		"-4g",
		"4 g",
		"g",
		"4gg",
		"1.5g",
		"999999999999999999999g",
	] {
		assert_eq!(parse_memory_size(value), None, "{value}");
	}
}

/// The shape and the read are two rules, and `stack resources set` answers a
/// value of the right shape that no 64-bit size reaches with its own message.
/// Folding the overflow into the shape check is what moved that message, so
/// the boundary is pinned here.
#[test]
fn the_shape_holds_for_a_value_the_read_cannot_reach() {
	let past_u64 = "99999999999g";
	assert!(
		is_memory_size_shape(past_u64),
		"a value written the compose way is the right shape whatever it holds"
	);
	assert_eq!(
		parse_memory_size(past_u64),
		None,
		"but no 64-bit size reaches it"
	);
	for value in ["", "4", "4t", "-4g", "1.5g", "g", "4gg", "0g", "00m"] {
		assert!(
			!is_memory_size_shape(value),
			"{value:?} is not a memory size of the compose shape"
		);
	}
	for value in ["64k", "512M", "4g", "4G", "1k"] {
		assert!(
			is_memory_size_shape(value),
			"{value:?} is the compose shape"
		);
		assert!(parse_memory_size(value).is_some(), "{value:?} reads");
	}
}

#[test]
fn the_rfc_length_caps_are_the_numbers_the_standards_name() {
	assert_eq!(MAX_ADDRESS, 254);
	assert_eq!(MAX_LOCAL_PART, 64);
	assert_eq!(MAX_DOMAIN, 253);
	assert_eq!(MAX_LABEL, 63);
}
