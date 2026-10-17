//! Characters that are not controls and still change what a terminal shows:
//! they reorder text, take no room, or draw as blank. A name or a note read
//! from a file and printed as it is could use them to make one thing look
//! like another.

/// Whether `c` reorders, hides or blanks text without being a control
/// character (those are `char::is_control`'s). The whole Unicode format
/// category is covered, and the default-ignorable code points that are not in
/// it but draw as nothing.
pub fn is_hidden(c: char) -> bool {
	matches!(
		c,
		// soft hyphen, combining grapheme joiner, Arabic letter mark
		'\u{00ad}' | '\u{034f}' | '\u{061c}'
			// Hangul and Khmer fillers
			| '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}'
			// Mongolian free variation selectors and vowel separator
			| '\u{180b}'..='\u{180f}'
			// zero-width and direction marks, line and paragraph
			// separators, embeddings and overrides, invisible operators,
			// isolates and the deprecated format controls
			| '\u{200b}'..='\u{200f}'
			| '\u{2028}'..='\u{202e}'
			| '\u{2060}'..='\u{206f}'
			// braille blank, Hangul fillers
			| '\u{2800}' | '\u{3164}' | '\u{ffa0}'
			// variation selectors, byte order mark, interlinear annotation
			| '\u{fe00}'..='\u{fe0f}'
			| '\u{feff}'
			| '\u{fff9}'..='\u{fffb}'
			// shorthand and musical format controls
			| '\u{1bca0}'..='\u{1bca3}'
			| '\u{1d173}'..='\u{1d17a}'
			// tags and the supplementary variation selectors
			| '\u{e0000}'..='\u{e007f}'
			| '\u{e0100}'..='\u{e01ef}'
	)
}

#[cfg(test)]
#[path = "hidden_tests.rs"]
mod tests;
