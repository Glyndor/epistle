use super::*;

fn tally(attempted: u32, deferred: u32, bounced: u32, spam_blocks: u32) -> Tally {
	Tally {
		attempted,
		deferred,
		bounced,
		spam_blocks,
	}
}

#[test]
fn a_provider_day_is_judged_on_the_documented_thresholds() {
	let cases = [
		(tally(0, 0, 0, 0), Verdict::Idle),
		(tally(100, 1, 1, 0), Verdict::Good),
		(tally(100, 2, 0, 0), Verdict::Bad),
		(tally(100, 0, 2, 0), Verdict::Bad),
		(tally(100, 10, 0, 0), Verdict::Bad),
		(tally(100, 11, 0, 0), Verdict::VeryBad),
		(tally(1000, 0, 0, 1), Verdict::VeryBad),
		(tally(100, 0, 50, 0), Verdict::Bad),
	];
	let got: Vec<_> = cases
		.iter()
		.map(|(counts, _)| (*counts, judge(Group::Gmail, counts)))
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn in_other_a_spam_refusal_counts_as_a_share_not_on_its_own() {
	let cases = [
		// One receiver refusing one message out of a hundred: the day stays good.
		(tally(100, 0, 0, 1), Verdict::Good),
		(tally(100, 0, 1, 1), Verdict::Bad),
		(tally(100, 0, 5, 5), Verdict::Bad),
		(tally(100, 0, 5, 6), Verdict::VeryBad),
		(tally(100, 11, 0, 0), Verdict::VeryBad),
	];
	let got: Vec<_> = cases
		.iter()
		.map(|(counts, _)| (*counts, judge(Group::Other, counts)))
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn the_cap_grows_by_half_until_it_is_lifted() {
	let mut caps = vec![START_CAP];
	while let Some(next) = grown(*caps.last().expect("a cap")) {
		caps.push(next);
	}
	assert_eq!(
		caps,
		[50, 75, 113, 170, 255, 383, 575, 863, 1295, 1943, 2915, 4373]
	);
}

#[test]
fn a_step_back_never_goes_under_the_start() {
	assert_eq!(step_back(113), 75);
	assert_eq!(step_back(75), 50);
	assert_eq!(step_back(50), 50);
	// A cap the operator set under the start stays where it is.
	assert_eq!(step_back(20), 20);
}

#[test]
fn a_day_grows_the_cap_only_when_half_of_it_was_used() {
	assert!(filled(25, 50));
	assert!(!filled(24, 50));
	assert!(filled(u32::MAX, u32::MAX));
}
