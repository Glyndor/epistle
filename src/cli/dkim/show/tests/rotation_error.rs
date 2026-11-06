use super::super::rotation_error::current;

const FAILED_AT: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z

fn line() -> Option<String> {
	Some(format!(
		"{FAILED_AT} rotation to s20260101 withdrawn: it does not show the new key in DNS\n"
	))
}

#[test]
fn the_failure_time_is_printed_as_a_date_not_as_an_epoch() {
	let text =
		current(line(), Some(FAILED_AT - 86_400)).expect("a failure after the last rotation");
	assert!(
		text.starts_with("rotation to s20260101 withdrawn"),
		"{text}"
	);
	assert!(text.ends_with("(2026-01-01T00:00:00Z)"), "{text}");
	assert!(!text.contains(&FAILED_AT.to_string()), "{text}");
}

#[test]
fn a_failure_older_than_the_key_now_signing_is_not_shown() {
	assert_eq!(current(line(), Some(FAILED_AT + 1)), None);
	assert_eq!(current(line(), Some(FAILED_AT)), None);
}

#[test]
fn a_line_without_a_time_is_shown_as_it_is() {
	let text = current(Some("something broke\n".into()), Some(5)).expect("shown");
	assert_eq!(text, "something broke");
}

#[test]
fn no_error_file_shows_nothing() {
	assert_eq!(current(None, Some(5)), None);
	assert_eq!(current(Some("  \n".into()), None), None);
}
