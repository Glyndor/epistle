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
