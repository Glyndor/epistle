//! The window of a text that is trained or scored on.

use super::*;

#[test]
fn the_window_keeps_the_start_and_the_end_and_never_cuts_a_character() {
	let mut text = "a".repeat(MAX_TRAINING_BYTES / 2 - 2);
	text.push('\u{1F600}');
	text.push_str(&"b ".repeat(MAX_TRAINING_BYTES));
	text.push('\u{1F600}');
	text.push_str("tail");
	let window = training_window(&text);
	assert!(window.len() <= MAX_TRAINING_BYTES);
	assert!(window.starts_with('a') && window.ends_with("tail"));
	assert!(window.contains('\n'));
}

/// The cut of the window on every byte of a character, for every width.
#[test]
fn no_shift_of_a_wide_text_makes_the_window_cut_a_character() {
	for unit in ["é", "日", "𝐚"] {
		for shift in 0..8 {
			let mut text = "q".repeat(shift);
			text.push_str(&unit.repeat(MAX_TRAINING_BYTES));
			text.push_str(" tail");
			let window = training_window(&text);
			assert!(window.len() <= MAX_TRAINING_BYTES);
			assert!(window.ends_with("tail") && window.contains('\n'));
		}
	}
}

#[test]
fn the_middle_of_a_long_text_is_left_out() {
	let text = format!(
		"head {} middle {} tail",
		"x ".repeat(MAX_TRAINING_BYTES / 2),
		"y ".repeat(MAX_TRAINING_BYTES / 2)
	);
	let window = training_window(&text);
	assert!(window.starts_with("head") && window.ends_with("tail"));
	assert!(!window.contains("middle"));
}

/// The seams of the window never leave half a word behind: a word cut by
/// the window would become a token nobody wrote.
#[test]
fn the_window_does_not_cut_a_word_at_its_seams() {
	for shift in 0..12 {
		let text = format!(
			"{}{}",
			"x".repeat(shift),
			"wordy ".repeat(3 * MAX_TRAINING_BYTES / 6)
		);
		let window = training_window(&text);
		assert!(window.len() <= MAX_TRAINING_BYTES);
		for token in window.split(|c: char| !c.is_alphanumeric()) {
			assert!(
				token.is_empty() || token.ends_with("wordy") || token.chars().all(|c| c == 'x'),
				"a fragment {token:?} appeared at a seam"
			);
		}
	}
}

#[test]
fn a_short_text_is_kept_whole() {
	assert!(matches!(
		training_window("short text"),
		Cow::Borrowed("short text")
	));
	assert_eq!(training_window(""), "");
	let exact = "a".repeat(MAX_TRAINING_BYTES);
	assert_eq!(training_window(&exact).len(), MAX_TRAINING_BYTES);
}
