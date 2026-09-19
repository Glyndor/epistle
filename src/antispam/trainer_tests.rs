//! Unit tests for the Bayes trainer abstraction.

use super::*;

#[test]
fn min_trusted_messages_is_a_nonzero_threshold() {
	// The threshold is the contract `score_for_account` honours: an
	// account below it falls back to the shared scope. A regression
	// that drops it to zero would silently misclassify users who have
	// never marked a message.
	const { assert!(MIN_TRUSTED_MESSAGES >= 1) }
}

#[test]
fn is_trusted_uses_the_threshold() {
	// Below the threshold on either side: untrained.
	let under_ham = Corpus {
		ham_messages: MIN_TRUSTED_MESSAGES - 1,
		spam_messages: MIN_TRUSTED_MESSAGES,
	};
	assert!(!is_trusted(under_ham));
	// At the threshold exactly on both sides: trusted. The boundary is
	// inclusive.
	let at_threshold = Corpus {
		ham_messages: MIN_TRUSTED_MESSAGES,
		spam_messages: MIN_TRUSTED_MESSAGES,
	};
	assert!(is_trusted(at_threshold));
	// Below the threshold on spam: untrained.
	let under_spam = Corpus {
		ham_messages: MIN_TRUSTED_MESSAGES,
		spam_messages: MIN_TRUSTED_MESSAGES - 1,
	};
	assert!(!is_trusted(under_spam));
}
