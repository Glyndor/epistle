//! Bounded authentication evaluation with counted, in-process DNS answers.

use std::future::Future;
use std::sync::atomic::Ordering;

use base64::Engine;
use epistle::arc::chain::{ChainError, ChainValidation};
use epistle::dkim::{DkimOutcome, DkimResult, verify_message};
use epistle::dmarc::{DmarcOutcome, evaluate, from_domain};
use epistle::spf::{SpfOutcome, check_host};

use super::harness::{Dns, bounded};

fn checked(work: impl Future<Output = ()> + Send + 'static) {
	bounded(move || {
		tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("parser runtime")
			.block_on(work);
	});
}

async fn spf(dns: &Dns) -> SpfOutcome {
	check_host(
		dns,
		"192.0.2.1".parse().expect("fixture IP"),
		"sender.test",
		"a@sender.test",
		"helo.test",
	)
	.await
}

#[test]
fn eleventh_spf_dns_term_is_permerror_without_eleventh_address_lookup() {
	checked(async {
		let terms = (0..11)
			.map(|n| format!("a:host{n}.test"))
			.collect::<Vec<_>>()
			.join(" ");
		let dns = Dns::default().with("sender.test", &format!("v=spf1 {terms} -all"));
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
		assert_eq!(dns.count(), 1);
		assert_eq!(dns.addresses.load(Ordering::SeqCst), 10);
		let control = Dns::default().with("sender.test", "v=spf1 ip4:192.0.2.1 -all");
		assert_eq!(spf(&control).await, SpfOutcome::Pass);
	});
}

#[test]
fn circular_spf_include_stops_at_shared_depth_budget() {
	checked(async {
		let dns = Dns::default()
			.with("sender.test", "v=spf1 include:other.test -all")
			.with("other.test", "v=spf1 include:sender.test -all");
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
		assert_eq!(dns.count(), 10);
	});
}

#[test]
fn circular_spf_redirect_stops_at_shared_depth_budget() {
	checked(async {
		let dns = Dns::default()
			.with("sender.test", "v=spf1 redirect=other.test")
			.with("other.test", "v=spf1 redirect=sender.test");
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
		assert_eq!(dns.count(), 10);
	});
}

#[test]
fn sibling_spf_includes_share_the_same_ten_term_budget() {
	checked(async {
		let child = "v=spf1 a:h1.test a:h2.test a:h3.test a:h4.test a:h5.test a:h6.test -all";
		let dns = Dns::default()
			.with(
				"sender.test",
				"v=spf1 include:first.test include:second.test -all",
			)
			.with("first.test", child)
			.with("second.test", child);
		assert_eq!(spf(&dns).await, SpfOutcome::PermError);
		assert_eq!(dns.count(), 3);
		assert_eq!(dns.addresses.load(Ordering::SeqCst), 8);
	});
}

fn signed(tags: &str) -> Vec<u8> {
	format!("From: a@sender.test\r\nDKIM-Signature: v=1; a=ed25519-sha256; d=sender.test; s=s; h=from; b=AA==; {tags}\r\n\r\nbody\r\n").into_bytes()
}

async fn dkim_reject(tags: &str, expected: DkimOutcome) {
	let dns = Dns::default();
	let results = verify_message(&dns, &signed(tags)).await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, expected);
	assert_eq!(dns.count(), 0, "invalid body/signature reached DNS");
}

#[test]
fn overflowing_dkim_body_length_is_permerror_before_dns() {
	checked(async {
		dkim_reject(
			&format!("l={}; bh=AA==", "9".repeat(10_000)),
			DkimOutcome::PermError,
		)
		.await;
	});
}

#[test]
fn maximum_usize_dkim_body_length_is_rejected_without_allocation_from_length() {
	checked(async {
		dkim_reject(
			&format!("l={}; bh=AA==", usize::MAX),
			DkimOutcome::PermError,
		)
		.await;
	});
}

#[test]
fn zero_dkim_body_length_cannot_authorize_appended_body() {
	checked(async {
		// Cover both skipping the length guard and truncating the hashed body.
		for body in [&b"body\r\n"[..], &b""[..]] {
			let digest = ring::digest::digest(&ring::digest::SHA256, body);
			let hash = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
			dkim_reject(&format!("l=0; bh={hash}"), DkimOutcome::Fail).await;
		}
	});
}

#[test]
fn giant_valid_base64_body_hash_fails_without_dns() {
	checked(async {
		dkim_reject(&format!("bh={}", "AAAA".repeat(250_000)), DkimOutcome::Fail).await;
	});
}

#[test]
fn malformed_dkim_body_hash_is_permerror_before_dns() {
	checked(async {
		dkim_reject("bh=!!!!", DkimOutcome::PermError).await;
	});
}

#[test]
fn ten_thousand_headers_do_not_hide_a_bad_dkim_signature() {
	checked(async {
		let mut raw = b"X-Padding: x\r\n".repeat(10_000);
		raw.extend(signed("l=0; bh=AA=="));
		let dns = Dns::default();
		let results = verify_message(&dns, &raw).await;
		assert_eq!(results.len(), 1);
		assert_eq!(results[0].outcome, DkimOutcome::Fail);
		assert_eq!(dns.count(), 0);
	});
}

#[test]
fn forged_authentication_results_and_reply_to_cannot_override_dmarc_reject() {
	checked(async {
		let raw = b"From: a@victim.test\r\nReply-To: a@evil.test\r\nReturn-Path: <a@evil.test>\r\nAuthentication-Results: victim.test; dkim=pass; spf=pass; dmarc=pass\r\n\r\nbody";
		let domain = from_domain(raw).expect("single author");
		assert_eq!(domain, "victim.test");
		let dns = Dns::default().with("_dmarc.victim.test", "v=DMARC1; p=reject; pct=100");
		let dkim = verify_message(&dns, raw).await;
		assert_eq!(
			evaluate(&dns, &domain, (SpfOutcome::Fail, Some("evil.test")), &dkim).await,
			DmarcOutcome::Reject
		);
		assert_eq!(dns.count(), 1);
	});
}

#[test]
fn unaligned_passing_signatures_do_not_pass_strict_dmarc() {
	checked(async {
		let dns = Dns::default().with("_dmarc.victim.test", "v=DMARC1; p=reject; aspf=s; adkim=s");
		let dkim = [DkimResult {
			outcome: DkimOutcome::Pass,
			domain: Some("evil.test".into()),
		}];
		assert_eq!(
			evaluate(
				&dns,
				"victim.test",
				(SpfOutcome::Pass, Some("evil.test")),
				&dkim
			)
			.await,
			DmarcOutcome::Reject
		);
		assert_eq!(dns.count(), 1);
		let aligned = [DkimResult {
			outcome: DkimOutcome::Pass,
			domain: Some("victim.test".into()),
		}];
		assert_eq!(
			evaluate(&dns, "victim.test", (SpfOutcome::Fail, None), &aligned).await,
			DmarcOutcome::Pass
		);
	});
}

#[test]
fn ten_thousand_from_headers_are_not_treated_as_one_dmarc_author() {
	checked(async {
		let mut raw = b"From: a@victim.test\r\n".repeat(10_000);
		raw.extend_from_slice(b"\r\nbody");
		assert_eq!(from_domain(&raw), None);
	});
}

#[test]
fn arc_instance_over_fifty_fails_before_dns() {
	checked(async {
		let dns = Dns::default();
		let raw = b"ARC-Seal: i=51; cv=pass\r\n\r\nbody";
		assert_eq!(
			epistle::arc::chain::extract(raw),
			Err(ChainError::BadInstance)
		);
		assert_eq!(
			epistle::arc::validate::validate(&dns, raw).await,
			ChainValidation::Fail
		);
		assert_eq!(dns.count(), 0);
	});
}

#[test]
fn ten_thousand_duplicate_arc_seals_fail_before_dns() {
	checked(async {
		let mut raw = b"ARC-Seal: i=1; cv=none\r\n".repeat(10_000);
		raw.extend_from_slice(b"\r\nbody");
		let dns = Dns::default();
		assert_eq!(
			epistle::arc::chain::extract(&raw),
			Err(ChainError::Duplicate)
		);
		assert_eq!(
			epistle::arc::validate::validate(&dns, &raw).await,
			ChainValidation::Fail
		);
		assert_eq!(dns.count(), 0);
	});
}

#[test]
fn incomplete_arc_chain_claiming_pass_fails_closed() {
	checked(async {
		let dns = Dns::default();
		let raw = b"ARC-Seal: i=1; cv=pass\r\nARC-Authentication-Results: i=1; victim.test; dmarc=pass\r\n\r\nbody";
		assert_eq!(
			epistle::arc::validate::validate(&dns, raw).await,
			ChainValidation::Fail
		);
		assert_eq!(dns.count(), 0);
	});
}

#[test]
fn dkim_header_flood_is_rejected_as_one_bounded_error() {
	checked(async {
		let mut raw = b"From: a@sender.test\r\n".to_vec();
		raw.extend(b"DKIM-Signature: invalid\r\n".repeat(10_000));
		raw.extend_from_slice(b"\r\nbody");
		let dns = Dns::default();
		let results = verify_message(&dns, &raw).await;
		assert_eq!(
			results.len(),
			1,
			"oversized header block must stop as one error"
		);
		assert_eq!(results[0].outcome, DkimOutcome::PermError);
		assert_eq!(dns.count(), 0);
	});
}
