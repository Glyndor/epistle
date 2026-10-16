use super::*;

const TODAY: Day = Day(20_740);

fn tight() -> Quota {
	Quota::new(Limits {
		account_accepted: 3,
		account_kept_bytes: 100,
		day_records: 10,
	})
}

#[test]
fn an_account_is_refused_past_its_acceptances_and_the_others_are_not() {
	let quota = tight();
	for _ in 0..3 {
		quota.admit("noisy", 0, TODAY).expect("within the limit");
		quota.charge(Some("noisy"), 1, 0, TODAY);
	}
	let refused = quota.admit("noisy", 0, TODAY).expect_err("past it");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	quota.admit("quiet", 0, TODAY).expect("another account");
}

#[test]
fn kept_bytes_are_counted_per_account() {
	let quota = tight();
	quota.charge(Some("a"), 1, 90, TODAY);
	quota.admit("a", 10, TODAY).expect("exactly the limit");
	quota.admit("a", 11, TODAY).expect_err("one byte over");
	quota.admit("b", 100, TODAY).expect("another account");
}

#[test]
fn the_whole_log_is_bounded_whoever_sent_the_records() {
	let quota = tight();
	for n in 0..10 {
		quota.charge(Some(&format!("a{n}")), 1, 0, TODAY);
	}
	assert!(quota.admit("fresh", 0, TODAY).is_err());
}

#[test]
fn outcomes_are_counted_but_never_refused_by_the_quota() {
	let quota = tight();
	// The outcomes of already accepted mail push the day past its limit.
	quota.charge(None, 12, 0, TODAY);
	assert!(quota.admit("a", 0, TODAY).is_err(), "new mail waits");
}

#[test]
fn a_new_day_starts_again() {
	let quota = tight();
	quota.charge(Some("a"), 3, 0, TODAY);
	assert!(quota.admit("a", 0, TODAY).is_err());
	quota.admit("a", 0, Day(TODAY.0 + 1)).expect("tomorrow");
}

#[test]
fn the_status_warns_before_the_limit() {
	let quota = Quota::new(Limits {
		account_accepted: 10,
		account_kept_bytes: u64::MAX,
		day_records: 1000,
	});
	assert_eq!(quota.warning(TODAY), None);
	quota.charge(Some("a"), 7, 0, TODAY);
	assert_eq!(quota.warning(TODAY), None, "70 percent");
	quota.charge(Some("a"), 1, 0, TODAY);
	assert!(
		quota
			.warning(TODAY)
			.expect("warning")
			.contains("near its evidence limits")
	);
}
