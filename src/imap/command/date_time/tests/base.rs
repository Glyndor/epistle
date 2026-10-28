use super::{InternalDate, UNIX_EPOCH, split_date_time};

fn seconds(date: InternalDate) -> u64 {
	date.time
		.duration_since(UNIX_EPOCH)
		.expect("after epoch")
		.as_secs()
}

#[test]
fn the_zone_is_folded_into_the_instant() {
	let (time, rest) = split_date_time("\"22-Feb-2008 23:00:00 +0200\" {5}").expect("valid");
	// 2008-02-22T21:00:00Z.
	assert_eq!(seconds(time.expect("date")), 1_203_714_000);
	assert_eq!(time.expect("date").zone, 120);
	assert_eq!(rest, "{5}");
	let (time, _) = split_date_time("\" 2-feb-2008 01:00:00 -0130\" {5}").expect("valid");
	// 2008-02-02T02:30:00Z.
	assert_eq!(seconds(time.expect("date")), 1_201_919_400);
	assert_eq!(time.expect("date").zone, -90);
}

#[test]
fn no_quote_means_no_date_and_a_bad_date_is_an_error() {
	assert_eq!(split_date_time("{5}"), Ok((None, "{5}")));
	for bad in [
		"\"30-Feb-2008 00:00:00 +0000\" {5}",
		"\"22-Foo-2008 00:00:00 +0000\" {5}",
		"\"22-Feb-2008 24:00:00 +0000\" {5}",
		"\"22-Feb-2008 00:00:00 0000\" {5}",
		"\"22-Feb-2008 00:00:00 +2400\" {5}",
		"\"22-Feb-2008 00:00:00 +0000 {5}",
	] {
		assert!(split_date_time(bad).is_err(), "{bad}");
	}
}
