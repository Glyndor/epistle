//! Tests for duplicate TXT detection in `txt_check`: one of the records at
//! a name must be unique (SPF, DMARC, MTA-STS at their canonical names;
//! DKIM at each `<selector>._domainkey`). Two records of the same tag at
//! the same name are a configuration mistake the resolver turns into a
//! permanent error: SPF returns `permerror` (RFC 7208 §4.5), DMARC is
//! ignored (RFC 7489 §6.6.3), and MTA-STS / TLS-RPT clients treat the name as
//! unconfigured. The check must report the duplicate, not silently pass.

use super::*;
use crate::dns::provider::txt_purpose;
use crate::spf::DnsFailure;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	mx: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	ptr: HashMap<IpAddr, Vec<String>>,
	fail: bool,
}

impl DnsLookup for FakeDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let result = if self.fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.addresses.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn mx(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.mx.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn ptr(
		&self,
		ip: IpAddr,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}
}

fn status(checks: &[Check], kind: &str) -> Status {
	checks
		.iter()
		.find(|c| c.kind == kind)
		.unwrap_or_else(|| panic!("no check {kind}"))
		.status
		.clone()
}

fn detail(checks: &[Check], kind: &str) -> String {
	checks
		.iter()
		.find(|c| c.kind == kind)
		.unwrap_or_else(|| panic!("no check {kind}"))
		.detail
		.clone()
}

/// `txt_purpose` recognises a case-insensitive Tag (`v=spf1`, `v=DMARC1`,
/// `v=DKIM1`, `v=STSv1`, `v=TLSRPTv1`) on every variant we expect a
/// provider to hand back: the leading-whitespace and quoted forms,
/// mixed case. The contract is the same on the matching side.
#[test]
fn txt_purpose_matches_every_casing_and_presentation_form() {
	for value in [
		"v=spf1 mx -all",
		"V=SPF1 mx -all",
		"  v=spf1 mx -all",
		"\"v=spf1 mx -all\"",
		"\"v=SPF1 -all\"",
	] {
		assert_eq!(txt_purpose(value), Some("v=spf1"), "got None for {value:?}");
	}
}

/// Two SPF records at the apex is a `permerror` per RFC 7208 §4.5. The
/// check must flag the duplicate with a message that names the count,
/// the record kind, the name where the duplicate lives, and tells the
/// operator to keep one — so they know which record to delete without
/// reading the DNS spec.
#[tokio::test]
async fn two_spf_records_at_the_apex_are_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec![
			"v=spf1 mx -all".into(),
			"v=spf1 include:_spf.google.com -all".into(),
		],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Missing);
	let d = detail(&checks, "SPF");
	assert!(d.contains("2 SPF records"), "detail missing count: {d:?}");
	assert!(d.contains("example.org"), "detail missing name: {d:?}");
	assert!(d.contains("keep one"), "detail missing action: {d:?}");
}

/// Two DMARC records at `_dmarc.<domain>` make receivers ignore the
/// policy per RFC 7489 §6.6.3. The check flags it with the same shape
/// as the SPF case so the operator gets a single, recognisable
/// pattern in the output.
#[tokio::test]
async fn two_dmarc_records_are_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"_dmarc.example.org".into(),
		vec!["v=DMARC1; p=none".into(), "v=DMARC1; p=reject".into()],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "DMARC"), Status::Missing);
	let d = detail(&checks, "DMARC");
	assert!(d.contains("2 DMARC records"), "detail: {d:?}");
	assert!(d.contains("_dmarc.example.org"), "detail: {d:?}");
	assert!(d.contains("keep one"), "detail: {d:?}");
}

/// Two MTA-STS records at `_mta-sts.<domain>` break the lookup
/// (RFC 8461 §3.1 — SVRls observes both nameservers and treats the
/// lookup as inconclusive). The check flags it with the same shape.
#[tokio::test]
async fn two_mta_sts_records_are_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"_mta-sts.example.org".into(),
		vec!["v=STSv1; id=1".into(), "v=STSv1; id=2".into()],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "MTA-STS"), Status::Missing);
	let d = detail(&checks, "MTA-STS");
	assert!(d.contains("2 MTA-STS records"), "detail: {d:?}");
	assert!(d.contains("_mta-sts.example.org"), "detail: {d:?}");
	assert!(d.contains("keep one"), "detail: {d:?}");
}

/// DKIM at one selector — two records with the same `v=DKIM1` tag at
/// the same `<selector>._domainkey` name — is a duplicate. Multiple
/// selectors at the same domain are normal (Ed25519 + RSA dual
/// signing), but two at the same selector name is the same bug.
#[tokio::test]
async fn two_dkim_records_at_the_same_selector_are_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"mail._domainkey.example.org".into(),
		vec![
			"v=DKIM1; k=ed25519; p=AAAA".into(),
			"v=DKIM1; k=rsa; p=BBBB".into(),
		],
	);
	let checks = check_domain(
		"example.org",
		"mail.example.org",
		&["mail".to_string()],
		&dns,
	)
	.await;
	assert_eq!(status(&checks, "DKIM mail"), Status::Missing);
	let d = detail(&checks, "DKIM mail");
	assert!(d.contains("2 DKIM"), "detail: {d:?}");
	assert!(d.contains("mail._domainkey.example.org"), "detail: {d:?}");
	assert!(d.contains("keep one"), "detail: {d:?}");
}

/// Two DKIM selectors at the same domain are normal (Ed25519 + RSA),
/// not a duplicate. The check looks at each selector name in
/// isolation, so a second selector at its own `_domainkey` name does
/// not trip the duplicate rule.
#[tokio::test]
async fn two_dkim_selectors_at_different_names_are_ok() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"ed._domainkey.example.org".into(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".into()],
	);
	dns.txt.insert(
		"rsa._domainkey.example.org".into(),
		vec!["v=DKIM1; k=rsa; p=BBBB".into()],
	);
	let checks = check_domain(
		"example.org",
		"mail.example.org",
		&["ed".to_string(), "rsa".to_string()],
		&dns,
	)
	.await;
	assert_eq!(status(&checks, "DKIM ed"), Status::Ok);
	assert_eq!(status(&checks, "DKIM rsa"), Status::Ok);
}

/// A single SPF record plus one unrelated TXT (no recognised tag —
/// the ACME DNS-01 challenge, a domain-verification token) at the
/// apex is fine. The unrelated record does not count toward the SPF
/// total because `txt_purpose` returns `None` for it.
#[tokio::test]
async fn one_spf_and_one_unrelated_txt_does_not_flag_a_match() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec![
			"v=spf1 mx -all".into(),
			"google-site-verification=abc123".into(),
		],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Ok);
}

/// Two SPF records written with different cases / presentation shapes
/// still match the same `v=spf1` tag, so the duplicate rule still
/// fires. The contract is the same one `txt_purpose` already covers.
#[tokio::test]
async fn duplicate_spf_with_mixed_case_and_quoted_form_is_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec![
			"V=SPF1 mx -all".into(),
			"\"v=spf1 include:_spf.google.com -all\"".into(),
		],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Missing);
	let d = detail(&checks, "SPF");
	assert!(d.contains("2 SPF records"), "detail: {d:?}");
}

/// A single SPF record quoted (the presentation form some providers
/// hand back) still counts as one, not two. The matching goes through
/// `txt_purpose`, which reads the quoted form back to its logical
/// value before tagging it.
#[tokio::test]
async fn one_quoted_spf_does_not_double_count() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt
		.insert("example.org".into(), vec!["\"v=spf1 mx -all\"".into()]);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Ok);
}

/// A name with two SPF records and one unrelated TXT reports the SPF
/// duplicate and ignores the unrelated record. The check does not
/// raise the unrelated TXT as anything (it has no recognised tag).
#[tokio::test]
async fn two_spf_with_one_unrelated_txt_still_reports_the_spf_duplicate() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec![
			"v=spf1 mx -all".into(),
			"v=spf1 include:_spf.google.com -all".into(),
			"google-site-verification=abc123".into(),
		],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Missing);
}

/// Two SPF records with leading whitespace around the tag still match
/// the `v=spf1` purpose, so the duplicate rule still fires.
#[tokio::test]
async fn duplicate_spf_with_leading_whitespace_is_reported() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec!["  v=spf1 mx -all".into(), "\tv=spf1 -all".into()],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Missing);
}

/// Three SPF records is still a duplicate — the message names the
/// exact count, not just "more than one", so they can grep for it.
#[tokio::test]
async fn three_spf_records_reports_the_exact_count() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt.insert(
		"example.org".into(),
		vec![
			"v=spf1 mx -all".into(),
			"v=spf1 include:_spf.google.com -all".into(),
			"v=spf1 -all".into(),
		],
	);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "SPF"), Status::Missing);
	let d = detail(&checks, "SPF");
	assert!(d.contains("3 SPF records"), "detail: {d:?}");
}
