use super::*;

#[test]
fn verdict_unknown_below_threshold() {
	assert_eq!(
		ReputationScore { ham: 1, spam: 1 }.verdict(),
		Verdict::Unknown
	);
}

#[test]
fn verdict_trusted_when_ham_leads() {
	assert_eq!(
		ReputationScore { ham: 5, spam: 1 }.verdict(),
		Verdict::Trusted
	);
	// Ties favor trust (benefit of the doubt above the threshold).
	assert_eq!(
		ReputationScore { ham: 2, spam: 2 }.verdict(),
		Verdict::Trusted
	);
}

#[test]
fn verdict_suspect_when_spam_leads() {
	assert_eq!(
		ReputationScore { ham: 1, spam: 5 }.verdict(),
		Verdict::Suspect
	);
}

#[test]
fn the_default_verdict_needs_three_observations() {
	let score = ReputationScore { ham: 0, spam: 2 };
	assert_eq!(score.verdict(), Verdict::Unknown);
	assert_eq!(score.verdict(), score.verdict_with(MIN_OBSERVATIONS));
}

#[test]
fn a_higher_floor_keeps_a_domain_unknown_for_longer() {
	let score = ReputationScore { ham: 1, spam: 5 };
	assert_eq!(score.verdict_with(3), Verdict::Suspect);
	assert_eq!(score.verdict_with(6), Verdict::Suspect);
	assert_eq!(score.verdict_with(7), Verdict::Unknown);
}
