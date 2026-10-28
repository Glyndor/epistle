//! Classification of remote replies by basic code and enhanced status.

use super::*;

#[test]
fn every_class_of_failure_has_its_own_verdict() {
	use FailureClass::*;
	// (reply, class, permanent, suppress)
	let cases = [
		("550 5.1.1 no such user", InvalidAddress, true, true),
		(
			"550 5.1.2 bad destination domain",
			InvalidAddress,
			true,
			true,
		),
		("556 5.1.10 null MX", InvalidAddress, true, true),
		("553 5.1.3 bad address syntax", InvalidAddress, true, true),
		// The sender's address, not the recipient's: never suppress.
		("550 5.1.8 bad sender domain", Other, true, false),
		("550 5.2.1 mailbox disabled", Other, true, false),
		("552 5.2.2 mailbox full", MailboxFull, false, false),
		("452 4.2.2 mailbox full", MailboxFull, false, false),
		("552 5.3.4 message too big", TooBig, true, false),
		(
			"552 5.2.3 message length exceeds limit",
			TooBig,
			true,
			false,
		),
		("550 5.7.1 rejected by policy", PolicyRejected, true, false),
		(
			"550 5.7.26 unauthenticated mail",
			PolicyRejected,
			true,
			false,
		),
		("554 5.4.4 unable to route", Other, true, false),
		("451 4.7.1 greylisted", PolicyRejected, false, false),
		("421 4.4.2 timeout", Other, false, false),
		// Basic codes alone.
		("550 mailbox unavailable", Other, true, false),
		("551 user not local", InvalidAddress, true, true),
		("553 mailbox name not allowed", InvalidAddress, true, true),
		("552 storage allocation exceeded", MailboxFull, false, false),
		("554 transaction failed", Other, true, false),
		("450 mailbox busy", Other, false, false),
		// A status that contradicts the code is ignored.
		("550 4.2.2 odd", Other, true, false),
	];
	for (reply, class, permanent, suppress) in cases {
		let verdict = classify_reason(reply, true);
		assert_eq!(
			verdict,
			Verdict {
				class,
				permanent,
				suppress
			},
			"{reply}"
		);
	}
}

#[test]
fn a_local_reason_keeps_the_permanence_it_was_given() {
	let local = classify_reason("connection refused", false);
	assert_eq!(local.class, FailureClass::Other);
	assert!(!local.permanent && !local.suppress);
	assert!(classify_reason("transport policy rejects x.example", true).permanent);
}

#[test]
fn class_labels_are_stable() {
	let labels: Vec<&str> = [
		FailureClass::InvalidAddress,
		FailureClass::MailboxFull,
		FailureClass::PolicyRejected,
		FailureClass::TooBig,
		FailureClass::Other,
	]
	.iter()
	.map(|class| class.label())
	.collect();
	assert_eq!(
		labels,
		[
			"invalid_address",
			"mailbox_full",
			"policy_rejected",
			"too_big",
			"other"
		]
	);
}

#[test]
fn enhanced_codes_are_parsed_strictly() {
	assert_eq!(
		parse_enhanced("5.1.10"),
		Some(Enhanced {
			class: 5,
			subject: 1,
			detail: 10
		})
	);
	for bad in ["5.1", "5.1.1.1", "3.1.1", "5..1", "5.1.x", "5.1.1234"] {
		assert_eq!(parse_enhanced(bad), None, "{bad}");
	}
}
