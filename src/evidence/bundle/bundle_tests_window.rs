//! A token only dates the sending if it was issued close to the day.

use super::tests::{kept_stamped_at, key_of};
use super::*;
use crate::evidence::audit::tests::DAY;
use crate::evidence::test_support::at;

fn failed_checks(gen_time: u64) -> Vec<String> {
	let kept = kept_stamped_at(false, gen_time);
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	let selector = Selector::MessageId("<kept@example.org>".into());
	export(kept.dir.path(), &kept.crypto, &selector, &bundle).expect("export");
	super::tests::failures(
		&check(&bundle, &[kept.tsa.anchor], &[key_of(kept.dir.path())]).expect("check"),
	)
}

#[test]
fn a_token_issued_the_next_day_dates_the_sending() {
	assert_eq!(failed_checks(at(DAY + 1, 1)), Vec::<String>::new());
}

#[test]
fn a_token_issued_after_the_window_does_not() {
	let failed = failed_checks(at(DAY + 30, 1));
	assert_eq!(
		failed.first().map(String::as_str),
		Some(
			"2026-10-14: stamped within days of the day ending: the token was issued long after the day ended: it shows when the day was sealed, not when its mail was sent"
		),
		"{failed:?}"
	);
}
