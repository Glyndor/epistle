//! Oversized and high-cardinality resolver answers. The expected outcomes
//! come from RFC 7208 §4.5, RFC 7489 §6.6.3, and RFC 8461 §3.1.

use epistle::dmarc::DmarcOutcome;
use epistle::spf::SpfOutcome;

use super::harness::*;

#[test]
fn spf_64k_txt_is_permerror() {
	// Mutation: map record::parse errors to TempError in SPF fetch_record.
	bounded(async {
		let dns = Texts {
			owner: DOMAIN,
			records: vec![oversized("v=spf1 ")],
		};
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
	});
}

#[test]
fn dmarc_64k_txt_is_permerror() {
	// Mutation: map malformed DMARC records to TempError in lookup.
	bounded(async {
		let dns = Texts {
			owner: "_dmarc.sender.example",
			records: vec![oversized("v=DMARC1; p=")],
		};
		assert_eq!(dmarc(&dns).await, DmarcOutcome::PermError);
	});
}

#[test]
fn mtasts_64k_txt_with_invalid_id_is_not_a_policy() {
	// Mutation: return Temporary instead of the discovered id in observe_id.
	// RFC 8461 §3.1 limits id to 1..32 ASCII letters/digits.
	bounded(async {
		let dns = Texts {
			owner: "_mta-sts.sender.example",
			records: vec![oversized("v=STSv1; id=")],
		};
		assert_eq!(store().policy(&dns, DOMAIN).await, Ok(None));
	});
}

#[test]
fn spf_1000_records_are_permerror() {
	// Mutation: disable the second-record guard in SPF fetch_record.
	bounded(async {
		let dns = Texts {
			owner: DOMAIN,
			records: (0..1000)
				.map(|n| format!("v=spf1 -all exp=e{n}.example"))
				.collect(),
		};
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
	});
}

#[test]
fn dmarc_1000_records_do_not_select_the_first_policy() {
	// Mutation: disable the second-record guard in DMARC lookup.
	bounded(async {
		let dns = Texts {
			owner: "_dmarc.sender.example",
			records: (0..1000)
				.map(|n| format!("v=DMARC1; p=reject; rua=mailto:r{n}@sender.example"))
				.collect(),
		};
		assert_eq!(dmarc(&dns).await, DmarcOutcome::None);
	});
}

#[test]
fn mtasts_1000_records_do_not_select_the_first_policy() {
	// Mutation: return Temporary instead of the discovered id in observe_id.
	bounded(async {
		let dns = Texts {
			owner: "_mta-sts.sender.example",
			records: (0..1000).map(|n| format!("v=STSv1; id={n}")).collect(),
		};
		assert_eq!(store().policy(&dns, DOMAIN).await, Ok(None));
	});
}
