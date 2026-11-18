//! The policy the evaluated record published, which the aggregate report
//! quotes in `<policy_published>`.

use super::base::{TxtDns, dns};
use super::*;

async fn published(records: &[(&str, &str)], from: &str) -> Option<PublishedPolicy> {
	evaluate_detailed(&dns(records), from, (SpfOutcome::Fail, None), &[], 100)
		.await
		.1
}

#[tokio::test]
async fn the_record_of_the_from_domain_is_quoted_as_published() {
	let policy = published(
		&[(
			"_dmarc.example.org",
			"v=DMARC1; p=quarantine; sp=reject; pct=50",
		)],
		"example.org",
	)
	.await;
	assert_eq!(
		policy,
		Some(PublishedPolicy {
			policy: "quarantine",
			subdomain_policy: "reject",
			pct: 50,
		})
	);
}

#[tokio::test]
async fn p_none_is_a_published_policy() {
	let policy = published(&[("_dmarc.example.org", "v=DMARC1; p=none")], "example.org").await;
	assert_eq!(
		policy,
		Some(PublishedPolicy {
			policy: "none",
			subdomain_policy: "none",
			pct: 100,
		})
	);
}

#[tokio::test]
async fn an_inherited_record_is_quoted_with_both_of_its_policies() {
	// The subdomain has no record: the organizational one applies through
	// its `sp=`, and the report still quotes `p=` and `sp=` as published.
	let policy = published(
		&[("_dmarc.example.org", "v=DMARC1; p=reject; sp=none; pct=20")],
		"mail.example.org",
	)
	.await;
	assert_eq!(
		policy,
		Some(PublishedPolicy {
			policy: "reject",
			subdomain_policy: "none",
			pct: 20,
		})
	);
}

#[tokio::test]
async fn a_passing_message_still_reports_the_published_policy() {
	let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; pct=75")]);
	let (outcome, policy) = evaluate_detailed(
		&dns,
		"example.org",
		(SpfOutcome::Pass, Some("example.org")),
		&[],
		1,
	)
	.await;
	assert_eq!(outcome, DmarcOutcome::Pass);
	assert_eq!(
		policy,
		Some(PublishedPolicy {
			policy: "reject",
			subdomain_policy: "reject",
			pct: 75,
		})
	);
}

#[tokio::test]
async fn nothing_is_published_without_a_usable_record() {
	assert_eq!(published(&[], "example.org").await, None);
	assert_eq!(
		published(
			&[("_dmarc.example.org", "v=DMARC1; p=bogus")],
			"example.org"
		)
		.await,
		None
	);
	let failing = TxtDns {
		records: Default::default(),
		fail: true,
	};
	let (outcome, policy) =
		evaluate_detailed(&failing, "example.org", (SpfOutcome::Fail, None), &[], 100).await;
	assert_eq!(outcome, DmarcOutcome::TempError);
	assert_eq!(policy, None);
}
