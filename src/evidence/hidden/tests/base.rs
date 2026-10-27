use super::*;

#[test]
fn every_character_that_reorders_or_blanks_text_is_hidden() {
	for c in [
		'\u{00ad}',
		'\u{034f}',
		'\u{061c}',
		'\u{115f}',
		'\u{1160}',
		'\u{17b4}',
		'\u{180e}',
		'\u{200b}',
		'\u{200e}',
		'\u{200f}',
		'\u{2028}',
		'\u{2029}',
		'\u{202a}',
		'\u{202e}',
		'\u{2060}',
		'\u{2066}',
		'\u{2069}',
		'\u{206f}',
		'\u{2800}',
		'\u{3164}',
		'\u{fe0f}',
		'\u{feff}',
		'\u{ffa0}',
		'\u{fffa}',
		'\u{e0041}',
		'\u{e007f}',
		'\u{e0100}',
	] {
		assert!(is_hidden(c), "U+{:04X} was left showing", c as u32);
	}
}

#[test]
fn text_people_write_is_not_hidden() {
	for c in "aZ09 .-_@é日本語العربية".chars() {
		assert!(!is_hidden(c), "{c} is plain text");
	}
}
