//! Provider identities come from codes, with only the two explicit text exceptions.

use super::*;

#[test]
fn provider_codes_keep_their_cause_and_decision_when_wording_changes() {
	use ProviderCause::*;
	for (code, enhanced, cause, permanent, pauses, sentence) in [
		(
			550,
			"5.7.515",
			DomainAuthentication,
			true,
			false,
			"The sending domain does not meet the receiver's authentication requirements; run epistle verify-dns.",
		),
		(
			550,
			"5.7.26",
			Unauthenticated,
			true,
			false,
			"The receiver rejected an unauthenticated message; run epistle verify-dns.",
		),
		(
			421,
			"4.7.28",
			RateLimit,
			false,
			true,
			"The receiver limited the sending rate; run epistle check queue.",
		),
	] {
		for wording in [
			"",
			"unrelated wording",
			"mailbox does not exist",
			"new localized prose",
		] {
			let text = format!("{enhanced} {wording}");
			let reason = format!("{code} {text}");
			assert_eq!(provider_cause(&reason), Some(cause), "{reason}");
			assert_eq!(cause.sentence(), sentence);
			assert_eq!(cause.pauses(), pauses);
			assert_eq!(
				classify(code, &text),
				Verdict {
					class: FailureClass::PolicyRejected,
					permanent,
					suppress: false,
				}
			);
			assert_eq!(crate::queue::backoff::throttled(&reason), pauses);
		}
	}
}

#[test]
fn only_a_571_naming_an_ip_or_list_has_the_ip_cause() {
	for text in [
		"IP rejected",
		"192.0.2.19 denied",
		"[2001:db8::1] denied",
		"see a blocklist",
		"listed by Spamhaus",
		"on a list",
		"DNSBL refusal",
	] {
		let reason = format!("550 5.7.1 {text}");
		assert_eq!(
			provider_cause(&reason),
			Some(ProviderCause::IpOrList),
			"{reason}"
		);
		assert_eq!(
			classify_reason(&reason, true),
			Verdict {
				class: FailureClass::PolicyRejected,
				permanent: true,
				suppress: false,
			}
		);
		assert!(!crate::queue::backoff::throttled(&reason));
	}
	assert_eq!(
		ProviderCause::IpOrList.sentence(),
		"The receiver rejected the sending IP or a blocklist entry; run epistle check dns."
	);
	for reason in [
		"550 5.7.1 policy refusal",
		"550 5.7.1 recipient refused",
		"550 5.7.1 playlist",
	] {
		assert_eq!(provider_cause(reason), None, "{reason}");
	}
}

#[test]
fn yahoo_requires_a_temporary_reply_and_the_machine_marker() {
	for reason in [
		"421 4.7.0 [TSS04] changed prose",
		"451 [TSS04] anything",
		"450 4.3.0 random [tss04]",
		"421 [TSS04]",
	] {
		assert_eq!(provider_cause(reason), Some(ProviderCause::YahooThrottle));
		assert!(!classify_reason(reason, true).permanent);
		assert!(!classify_reason(reason, true).suppress);
		assert!(crate::queue::backoff::throttled(reason));
	}
	assert_eq!(
		ProviderCause::YahooThrottle.sentence(),
		"Yahoo temporarily throttled the sender (TSS04); run epistle check queue."
	);
	for reason in [
		"550 5.7.0 [TSS04]",
		"421 throttled by Yahoo",
		"421 [TSS040]",
		"421 [XTSS04]",
		"250 [TSS04]",
	] {
		assert_eq!(provider_cause(reason), None, "{reason}");
	}
}

#[test]
fn unknown_missing_and_contradictory_enhanced_codes_stay_generic() {
	for reason in [
		"550 5.7.999 unauthenticated IP on list",
		"550 5.7.28 rate limit",
		"550 4.7.28 rate limit",
		"421 5.7.26 unauthenticated",
		"550 5.7.5150 refusal",
		"550 authentication requirements of the sending domain",
		"550 SPF DKIM DMARC",
		"550 5.3.4 IP listed",
		"local error 5.7.515",
	] {
		assert_eq!(provider_cause(reason), None, "{reason}");
	}
	assert_eq!(
		classify_reason("550 5.7.999 unauthenticated", false),
		Verdict {
			class: FailureClass::PolicyRejected,
			permanent: true,
			suppress: false,
		}
	);
	assert_eq!(
		classify_reason("450 4.9.99 rate limited", true),
		Verdict {
			class: FailureClass::Other,
			permanent: false,
			suppress: false,
		}
	);
	assert!(!crate::queue::backoff::throttled("450 4.9.99 rate limited"));
}

#[test]
fn a_bare_553_only_suppresses_an_explicit_mailbox_error() {
	for (text, suppress) in [
		("No such user", true),
		("mailbox does not exist", true),
		("unknown recipient", true),
		("mailbox not found", true),
		("mailbox name not allowed for this user", true),
		("mailbox not allowed for that user", true),
		("mailbox name not allowed", false),
		("policy rejection", false),
		("sender IP is on a blocklist", false),
		("SPF authentication failed", false),
		("relay access denied", false),
		("", false),
		("sender address rejected: user unknown", false),
		("policy rejection: no such user", false),
		("5.7.26 no such user", false),
		("5.2.1 unknown recipient", false),
	] {
		assert_eq!(
			classify(553, text),
			Verdict {
				class: if suppress {
					FailureClass::InvalidAddress
				} else if text.starts_with("5.7.") {
					FailureClass::PolicyRejected
				} else {
					FailureClass::Other
				},
				permanent: true,
				suppress,
			},
			"{text}"
		);
	}
	assert!(classify(553, "5.1.1 changed wording").suppress);
}
