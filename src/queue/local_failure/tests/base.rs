//! The reason a local failure writes, and its reading back.

use super::*;

const ALL: [LocalFailure; 8] = [
	LocalFailure::TlsRequired,
	LocalFailure::TlsaMismatch,
	LocalFailure::TlsaLookup,
	LocalFailure::Handshake,
	LocalFailure::MtaStsNoServer,
	LocalFailure::Dnssec,
	LocalFailure::Unreachable,
	LocalFailure::MxLookup,
];

#[test]
fn every_failure_reads_back_as_its_own_status_and_sentence() {
	for failure in ALL {
		let DeliveryError::Transient(reason) = failure.transient("mx.example.net", "detail") else {
			panic!("a local failure is retried");
		};
		let (enhanced, sentence) = parse(&reason).expect("a status");
		assert_eq!(enhanced.class, 4, "{reason}");
		assert_eq!((enhanced.subject, enhanced.detail), failure.status());
		assert!(sentence.contains("mx.example.net"), "{reason}");
		assert!(!sentence.contains("detail"), "{reason}");
	}
}

#[test]
fn encryption_required_has_its_own_code_and_the_rest_of_tls_is_a_crypto_failure() {
	assert_eq!(LocalFailure::TlsRequired.status(), (7, 10));
	for failure in [
		LocalFailure::TlsaMismatch,
		LocalFailure::TlsaLookup,
		LocalFailure::Handshake,
		LocalFailure::MtaStsNoServer,
		LocalFailure::Dnssec,
	] {
		assert_eq!(failure.status(), (7, 5));
	}
	assert_eq!(LocalFailure::Unreachable.status(), (4, 1));
	assert_eq!(LocalFailure::MxLookup.status(), (4, 3));
}

#[test]
fn a_remote_reply_and_a_plain_local_reason_carry_no_local_status() {
	assert!(parse("550 5.1.1 no such user").is_none());
	assert!(parse("timed out after 300s waiting for the greeting").is_none());
	assert!(parse("4.7.5").is_none());
	assert!(parse("4.7.5 ").is_none());
}

#[test]
fn a_local_reason_is_never_read_as_a_slow_down_or_a_remote_policy_refusal() {
	// `4.7.5` and `4.7.10` are enhanced statuses of subject 7, which the
	// queue reads from a server's reply to hold a whole provider; a reason
	// that starts with one and no reply code is not such a reply.
	for failure in ALL {
		let DeliveryError::Transient(reason) = failure.transient("mx.example.net", "detail") else {
			panic!("a local failure is retried");
		};
		assert!(!crate::queue::backoff::throttled(&reason), "{reason}");
		let verdict = crate::queue::reply::classify_reason(&reason, false);
		assert_eq!(verdict.class, crate::queue::reply::FailureClass::Other);
		assert!(!verdict.permanent && !verdict.suppress, "{reason}");
		assert!(
			crate::queue::reply::provider_cause(&reason).is_none(),
			"{reason}"
		);
	}
}
