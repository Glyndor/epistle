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

#[tokio::test]
async fn ptr_missing_is_reported_with_the_provider_hint() {
	// No PTR at all: the message tells the operator the missing record
	// is owned by the IP provider (the VPS / host), not their DNS zone,
	// so they know who to ask.
	let mut dns = FakeDns::default();
	let ip: IpAddr = "203.0.113.10".parse().unwrap();
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	let checks = check_host("mail.example.org", None, None, &dns).await;
	assert_eq!(status(&checks, &format!("PTR {ip}")), Status::Missing);
	let detail = detail(&checks, &format!("PTR {ip}"));
	assert!(
		detail.contains("no reverse record"),
		"detail was {detail:?}"
	);
	assert!(
		detail.contains("mail.example.org"),
		"detail must name the hostname, got {detail:?}"
	);
	assert!(
		detail.contains("provider"),
		"detail must point the operator at the IP provider, got {detail:?}"
	);
}

#[tokio::test]
async fn ptr_pointing_elsewhere_names_the_other_host() {
	// The PTR exists but points at a different name. This is the most
	// common real-world failure mode: the operator moves the hostname
	// to a new IP and the old PTR stays in place.
	let mut dns = FakeDns::default();
	let ip: IpAddr = "203.0.113.10".parse().unwrap();
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	dns.ptr.insert(ip, vec!["other.example".into()]);
	let checks = check_host("mail.example.org", None, None, &dns).await;
	assert_eq!(status(&checks, &format!("PTR {ip}")), Status::Missing);
	let detail = detail(&checks, &format!("PTR {ip}"));
	assert!(
		detail.contains("points at") && detail.contains("other.example"),
		"detail must name the wrong host, got {detail:?}"
	);
	assert!(
		detail.contains("mail.example.org"),
		"detail must state what the PTR should have been, got {detail:?}"
	);
}

#[tokio::test]
async fn ptr_without_forward_confirmation_is_reported() {
	// The PTR points at our hostname, but the hostname does NOT resolve
	// back to this IP. Forward and reverse are out of sync: receivers
	// that do forward-confirmation check would still treat this as
	// mismatch. The detail names the broken half. With public_ipv4 set
	// to the IP we expect, the check_host walks that IP's PTR and then
	// looks the hostname back up; the second lookup returns a different
	// IP, so the round trip is broken.
	let mut dns = FakeDns::default();
	let ip: IpAddr = "203.0.113.10".parse().unwrap();
	dns.addresses.insert(
		"mail.example.org".into(),
		vec!["198.51.100.7".parse().unwrap()],
	);
	dns.ptr.insert(ip, vec!["mail.example.org".into()]);
	let checks = check_host(
		"mail.example.org",
		Some("203.0.113.10".parse().unwrap()),
		None,
		&dns,
	)
	.await;
	assert_eq!(status(&checks, &format!("PTR {ip}")), Status::Missing);
	let detail = detail(&checks, &format!("PTR {ip}"));
	assert!(
		detail.contains("does not resolve back"),
		"detail must call out the broken round trip, got {detail:?}"
	);
	assert!(
		detail.contains(&ip.to_string()),
		"detail must name the IP, got {detail:?}"
	);
}

#[tokio::test]
async fn ptr_forward_confirmed_is_ok() {
	// The PTR points at the hostname, and the hostname resolves back to
	// the same IP, which is forward-confirmed reverse DNS, the happy path.
	let mut dns = FakeDns::default();
	let ip: IpAddr = "203.0.113.10".parse().unwrap();
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	dns.ptr.insert(ip, vec!["mail.example.org".into()]);
	let checks = check_host("mail.example.org", None, None, &dns).await;
	assert_eq!(status(&checks, &format!("PTR {ip}")), Status::Ok);
	assert!(
		detail(&checks, &format!("PTR {ip}")).contains("mail.example.org"),
		"detail must echo the hostname for grep-ability, got {}",
		detail(&checks, &format!("PTR {ip}"))
	);
}

#[tokio::test]
async fn configured_address_must_match_the_hostname_a_record() {
	// With public_ipv4 set, the hostname must resolve to exactly that
	// address. A different address in the A record is Missing with the
	// detail naming both the configured and the published address.
	let mut dns = FakeDns::default();
	dns.addresses.insert(
		"mail.example.org".into(),
		vec!["198.51.100.7".parse().unwrap()],
	);
	let checks = check_host(
		"mail.example.org",
		Some("203.0.113.10".parse().unwrap()),
		None,
		&dns,
	)
	.await;
	assert_eq!(status(&checks, "A"), Status::Missing);
	let detail = detail(&checks, "A");
	assert!(
		detail.contains("198.51.100.7") && detail.contains("203.0.113.10"),
		"detail must name both the configured and the resolved address, got {detail:?}"
	);
}

#[tokio::test]
async fn without_configured_addresses_the_resolved_ones_are_checked() {
	// With neither address configured, the resolver's answer is the
	// truth and the PTR check walks that set. The A/AAAA line reports
	// the resolved addresses verbatim.
	let mut dns = FakeDns::default();
	let ipv4: IpAddr = "203.0.113.10".parse().unwrap();
	let ipv6: IpAddr = "2001:db8::10".parse().unwrap();
	dns.addresses
		.insert("mail.example.org".into(), vec![ipv4, ipv6]);
	dns.ptr.insert(ipv4, vec!["mail.example.org".into()]);
	dns.ptr.insert(ipv6, vec!["mail.example.org".into()]);
	let checks = check_host("mail.example.org", None, None, &dns).await;
	let aa = status(&checks, "A/AAAA");
	assert_eq!(aa, Status::Ok);
	assert!(
		detail(&checks, "A/AAAA").contains(&ipv4.to_string())
			&& detail(&checks, "A/AAAA").contains(&ipv6.to_string()),
		"detail must list every resolved address, got {:?}",
		detail(&checks, "A/AAAA")
	);
	assert_eq!(status(&checks, &format!("PTR {ipv4}")), Status::Ok);
	assert_eq!(status(&checks, &format!("PTR {ipv6}")), Status::Ok);
	assert!(all_ok(&checks), "{checks:?}");
}
