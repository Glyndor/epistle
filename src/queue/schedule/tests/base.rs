use super::*;

#[test]
fn waits_double_from_the_base_up_to_the_cap() {
	let schedule = RetrySchedule {
		base: 300,
		cap: 1000,
		delay_warning: 7200,
	};
	let waits: Vec<u64> = (1..=5).map(|n| schedule.wait(n, 1.0)).collect();
	assert_eq!(waits, [300, 600, 1000, 1000, 1000]);
}

#[test]
fn the_spread_stays_within_twenty_percent() {
	let schedule = RetrySchedule::default();
	assert_eq!(schedule.wait(1, 0.8), 48);
	assert_eq!(schedule.wait(1, 1.2), 72);
	// A factor outside the band is clamped to it.
	assert_eq!(schedule.wait(1, 5.0), 72);
	for _ in 0..1000 {
		let factor = random_factor();
		assert!((0.8..=1.2).contains(&factor), "{factor}");
	}
}

#[test]
fn zero_or_absent_values_keep_the_defaults() {
	assert_eq!(
		RetrySchedule::from_config(None, Some(0), None),
		RetrySchedule::default()
	);
	assert_eq!(
		RetrySchedule::from_config(Some(120), Some(600), Some(3600)),
		RetrySchedule {
			base: 120,
			cap: 600,
			delay_warning: 3600
		}
	);
}
