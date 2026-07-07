//! Tests for DNS drift detection, driven by a scripted resolver.

use super::*;
use crate::spf::DnsFailure;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	mx: HashMap<String, Vec<String>>,
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
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
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
}

fn status(checks: &[Check], kind: &str) -> Status {
	checks
		.iter()
		.find(|c| c.kind == kind)
		.unwrap_or_else(|| panic!("no check {kind}"))
		.status
		.clone()
}

#[tokio::test]
async fn fully_configured_domain_passes() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt
		.insert("example.org".into(), vec!["v=spf1 mx -all".into()]);
	dns.txt.insert(
		"_dmarc.example.org".into(),
		vec!["v=DMARC1; p=reject".into()],
	);
	dns.txt
		.insert("_mta-sts.example.org".into(), vec!["v=STSv1; id=1".into()]);
	dns.txt.insert(
		"mail._domainkey.example.org".into(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".into()],
	);

	let checks = check_domain(
		"example.org",
		"mail.example.org",
		&["mail".to_string()],
		&dns,
	)
	.await;
	assert!(all_ok(&checks), "{checks:?}");
	assert_eq!(status(&checks, "DKIM mail"), Status::Ok);
}

#[tokio::test]
async fn missing_records_are_reported() {
	let dns = FakeDns::default();
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert!(!all_ok(&checks), "{checks:?}");
	assert_eq!(status(&checks, "MX"), Status::Missing);
	assert_eq!(status(&checks, "SPF"), Status::Missing);
	assert_eq!(status(&checks, "DMARC"), Status::Missing);
	assert_eq!(status(&checks, "MTA-STS"), Status::Missing);
}

#[tokio::test]
async fn mx_to_wrong_host_is_drift() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.other.example".into()]);
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	assert_eq!(status(&checks, "MX"), Status::Missing);
}

#[tokio::test]
async fn lookup_failure_is_inconclusive_not_drift() {
	let dns = FakeDns {
		fail: true,
		..Default::default()
	};
	let checks = check_domain("example.org", "mail.example.org", &[], &dns).await;
	// Errors must not be counted as drift (all_ok stays true).
	assert!(all_ok(&checks), "{checks:?}");
	assert_eq!(status(&checks, "SPF"), Status::LookupError);
}
