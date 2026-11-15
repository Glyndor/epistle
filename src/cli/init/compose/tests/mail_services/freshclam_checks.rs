//! The updater's checks per day and its notification: `freshclam` runs
//! in a container of its own, so the `NotifyClamd` of the image's
//! configuration can never reach `clamd` and only logs a warning.

use super::*;
use crate::cli::init::compose::MAX_FRESHCLAM_CHECKS;

fn script(value: &serde_json::Value) -> String {
	value["services"]["freshclam"]["entrypoint"][4]
		.as_str()
		.expect("the updater runs one shell script")
		.to_string()
}

#[test]
fn freshclam_checks_twelve_times_a_day_by_default() {
	let value = render(&stack_answers(), true);
	assert!(script(&value).contains("--checks=12"), "{}", script(&value));
	assert!(
		value.get("x-epistle-freshclam-checks").is_none(),
		"a default is not recorded, so a later release may change it"
	);
}

#[test]
fn freshclam_checks_follow_the_answer_and_are_recorded() {
	let mut answers = stack_answers();
	answers.services.freshclam_checks = Some(24);
	let value = render(&answers, true);
	assert!(script(&value).contains("--checks=24"), "{}", script(&value));
	assert!(!script(&value).contains("--checks=12"));
	assert_eq!(value["x-epistle-freshclam-checks"], 24);
}

#[test]
fn freshclam_does_not_try_to_notify_a_clamd_it_cannot_reach() {
	let value = render(&stack_answers(), true);
	let text = script(&value);
	assert!(
		text.contains("grep -v '^NotifyClamd' /etc/clamav/freshclam.conf"),
		"the copy of the configuration loses NotifyClamd: {text}"
	);
	assert!(
		text.contains("--config-file=/var/log/clamav/freshclam.conf"),
		"freshclam must run on the copy, not on the image's file: {text}"
	);
}

#[test]
fn checks_per_day_outside_what_clamav_accepts_are_refused() {
	use crate::cli::init::answers::Invalid;
	for (checks, accepted) in [
		(0, false),
		(1, true),
		(MAX_FRESHCLAM_CHECKS, true),
		(51, false),
	] {
		let mut answers = stack_answers();
		answers.services.freshclam_checks = Some(checks);
		let result = answers.validate();
		let refused = result.as_ref().is_err_and(|errors| {
			errors.iter().any(|error| {
				matches!(error, Invalid::Resources { field, .. } if field == "services.freshclam_checks")
			})
		});
		assert_eq!(refused, !accepted, "{checks} checks a day: {result:?}");
	}
}
