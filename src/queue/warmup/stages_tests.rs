use super::*;

#[test]
fn the_age_picks_the_row() {
	let names: Vec<&str> = [0, 6, 7, 27, 28, 89, 90, 3650]
		.into_iter()
		.map(|age| stage(age).name)
		.collect();
	assert_eq!(
		names,
		[
			"new",
			"new",
			"weeks",
			"weeks",
			"months",
			"months",
			"established",
			"established"
		]
	);
}

#[test]
fn a_new_address_starts_small_and_an_old_one_near_its_volume() {
	let cases = [
		(0, Some(1000), Some(50)),
		(0, None, Some(50)),
		(14, Some(1000), Some(250)),
		(14, Some(100), Some(50)),
		(60, Some(1000), Some(500)),
		(180, Some(1000), Some(1000)),
		(180, Some(5000), Some(5000)),
		(180, Some(5001), None),
		(60, Some(20_000), None),
		(180, None, Some(50)),
	];
	let got: Vec<_> = cases
		.iter()
		.map(|(age, volume, _)| (*age, *volume, starting_cap(*age, *volume)))
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn days_to_reach_count_good_days_of_growth() {
	assert_eq!(days_to_reach(Some(50), Some(1000)), 8);
	assert_eq!(days_to_reach(Some(1000), Some(1000)), 0);
	assert_eq!(days_to_reach(None, Some(1000)), 0);
	// Without a volume: until the cap is lifted.
	assert_eq!(days_to_reach(Some(50), None), 12);
	assert_eq!(days_to_reach(Some(1), Some(u32::MAX)), 20);
}
