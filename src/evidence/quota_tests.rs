use super::*;

const TODAY: Day = Day(20_740);

fn tight() -> Quota {
	Quota::new(Limits {
		account_records: 6,
		account_kept_bytes: 100,
		day_records: 10,
	})
}

fn reserve(quota: &Quota, account: &str, records: u64, kept: u64) -> std::io::Result<Reservation> {
	quota.reserve(account, (records, kept), TODAY)
}

#[test]
fn an_account_is_refused_past_its_records_and_the_others_are_not() {
	let quota = tight();
	for _ in 0..3 {
		let _ = reserve(&quota, "noisy", 2, 0).expect("within the limit");
	}
	let refused = reserve(&quota, "noisy", 2, 0).expect_err("past it");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	let _ = reserve(&quota, "quiet", 2, 0).expect("another account");
}

#[test]
fn kept_bytes_are_counted_per_account() {
	let quota = tight();
	let _ = reserve(&quota, "a", 1, 90).expect("within");
	let _ = reserve(&quota, "a", 1, 10).expect("exactly the limit");
	reserve(&quota, "a", 1, 1).expect_err("one byte over");
	let _ = reserve(&quota, "b", 1, 100).expect("another account");
}

#[test]
fn the_whole_log_is_bounded_whoever_sent_the_records() {
	let quota = tight();
	let _ = reserve(&quota, "a", 5, 0).expect("a");
	let _ = reserve(&quota, "b", 5, 0).expect("b");
	assert!(reserve(&quota, "fresh", 1, 0).is_err());
}

#[test]
fn a_reservation_given_back_leaves_the_room() {
	let quota = tight();
	let held = reserve(&quota, "a", 6, 50).expect("all of it");
	reserve(&quota, "a", 1, 0).expect_err("full");
	quota.release(held);
	let _ = reserve(&quota, "a", 6, 50).expect("room again");
}

#[test]
fn a_new_day_starts_again() {
	let quota = tight();
	let _ = reserve(&quota, "a", 6, 0).expect("all of it");
	assert!(reserve(&quota, "a", 1, 0).is_err());
	let _ = quota
		.reserve("a", (1, 0), Day(TODAY.0 + 1))
		.expect("tomorrow");
}

#[test]
fn one_account_with_the_largest_fan_out_cannot_use_up_the_days_room() {
	// The defaults: an account's share is a tenth of the day.
	let limits = Limits::default();
	assert!(limits.account_records.saturating_mul(10) <= limits.day_records);
	let quota = Quota::new(limits);
	let fan_out = 101; // an acceptance, and an outcome for each of 100 recipients
	let mut taken = 0;
	while reserve_ok(&quota, "noisy", fan_out) {
		taken += fan_out;
	}
	assert!(taken <= limits.account_records);
	let _ = reserve(&quota, "other", fan_out, 0).expect("another account is not held up");
}

fn reserve_ok(quota: &Quota, account: &str, records: u64) -> bool {
	reserve(quota, account, records, 0).is_ok()
}

#[test]
fn the_status_warns_before_the_limit() {
	let quota = Quota::new(Limits {
		account_records: 10,
		account_kept_bytes: u64::MAX,
		day_records: 1000,
	});
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 7, 0).expect("70 percent");
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 1, 0).expect("80 percent");
	assert!(
		quota
			.warning(TODAY)
			.expect("warning")
			.contains("near its evidence limits")
	);
}
