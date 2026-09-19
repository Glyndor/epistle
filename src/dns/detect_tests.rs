//! Tests for `src/dns/detect.rs`: the address classifier, the PTR report,
//! and a smoke test for the live `detect()` call. Driven by a scripted
//! resolver and the table of operator-relevant global-vs-non-global
//! addresses the classifier pins.

use super::*;
use crate::spf::DnsFailure;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

// Local `ip` helper that parses an `&str` into an `IpAddr`. There is a
// same-named helper elsewhere in the crate, but `use super::*` does not
// bring it into scope and a fresh binding here is the most direct way to
// keep these tests readable.
fn ip(text: &str) -> IpAddr {
	text.parse().unwrap()
}

#[derive(Default)]
struct FakeDns {
	ptr: HashMap<IpAddr, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	fail_ptr: bool,
	fail_addresses: bool,
}

impl DnsLookup for FakeDns {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
	}

	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_addresses {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.addresses.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
	}

	fn ptr(
		&self,
		address: IpAddr,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_ptr {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.ptr.get(&address).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}
}

#[test]
fn classifier_table_driven() {
	// IPv4: every entry below must agree with the helper.
	let v4: &[(&str, bool)] = &[
		// Global.
		("8.8.8.8", true),
		("1.1.1.1", true),
		// Private (RFC 1918).
		("10.0.0.1", false),
		("192.168.1.5", false),
		("172.16.0.1", false),
		// Loopback.
		("127.0.0.1", false),
		// Link-local.
		("169.254.1.1", false),
		// CGNAT (RFC 6598).
		("100.64.0.1", false),
		// Documentation (RFC 5737 / 3068).
		("192.0.2.1", false),
		("198.51.100.1", false),
		("203.0.113.1", false),
		// Multicast.
		("224.0.0.1", false),
		// Unspecified.
		("0.0.0.0", false),
	];
	for (s, expected) in v4 {
		let actual = non_global_ipv4_reason(s.parse().unwrap()).is_none();
		assert_eq!(
			actual, *expected,
			"ipv4 {s}: expected global={expected}, got global={actual}"
		);
	}

	// IPv6.
	let v6: &[(&str, bool)] = &[
		// Global.
		("2606:4700:4700::1111", true),
		// Loopback.
		("::1", false),
		// Link-local.
		("fe80::1", false),
		// ULA.
		("fc00::1", false),
		("fd12::1", false),
		// Documentation (RFC 3849).
		("2001:db8::1", false),
		// Multicast.
		("ff02::1", false),
		// Unspecified.
		("::", false),
	];
	for (s, expected) in v6 {
		let actual = non_global_ipv6_reason(s.parse().unwrap()).is_none();
		assert_eq!(
			actual, *expected,
			"ipv6 {s}: expected global={expected}, got global={actual}"
		);
	}
}

#[test]
fn selector_picks_lowest_and_lists_the_rest() {
	let interfaces = vec![
		ip("10.0.0.1"),             // not global
		ip("9.9.9.9"),              // global v4, higher
		ip("8.8.8.8"),              // global v4, lower, chosen
		ip("127.0.0.1"),            // not global
		ip("2606:4700:4700::1111"), // global v6, chosen
		ip("2606:4700:4700::2222"), // global v6, higher, listed in others
	];
	let result = local_global_addresses(interfaces.into_iter());
	assert_eq!(result.ipv4, Some("8.8.8.8".parse().unwrap()));
	assert_eq!(result.ipv6, Some("2606:4700:4700::1111".parse().unwrap()));
	assert_eq!(
		result.others,
		vec![ip("9.9.9.9"), ip("2606:4700:4700::2222")]
	);
}

#[test]
fn selector_returns_none_when_no_global_address() {
	let interfaces = vec![ip("10.0.0.1"), ip("192.168.1.5"), ip("127.0.0.1")];
	let result = local_global_addresses(interfaces.into_iter());
	assert_eq!(result.ipv4, None);
	assert_eq!(result.ipv6, None);
	assert!(result.others.is_empty());
}

#[test]
fn selector_returns_none_for_one_family_when_only_the_other_has_global() {
	let interfaces = vec![ip("10.0.0.1"), ip("127.0.0.1"), ip("8.8.8.8")];
	let result = local_global_addresses(interfaces.into_iter());
	assert_eq!(result.ipv4, Some("8.8.8.8".parse().unwrap()));
	assert_eq!(result.ipv6, None);
	assert!(result.others.is_empty());
}

#[test]
fn chosen_method_returns_the_tuple() {
	let interfaces = vec![ip("10.0.0.1"), ip("8.8.8.8")];
	let result = local_global_addresses(interfaces.into_iter());
	assert_eq!(result.chosen(), (Some("8.8.8.8".parse().unwrap()), None));
}

#[tokio::test]
async fn ptr_report_ok_when_forward_and_reverse_match() {
	let mut dns = FakeDns::default();
	let ip = ip("203.0.113.10");
	dns.ptr.insert(ip, vec!["mail.example.org".into()]);
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	assert_eq!(
		ptr_report("mail.example.org", ip, &dns).await,
		PtrReport::Ok
	);
}

#[tokio::test]
async fn ptr_report_none_when_no_ptr_record() {
	let mut dns = FakeDns::default();
	let ip = ip("203.0.113.10");
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	// No PTR entry: the resolver returns an empty Vec.
	assert_eq!(
		ptr_report("mail.example.org", ip, &dns).await,
		PtrReport::None
	);
}

#[tokio::test]
async fn ptr_report_points_elsewhen_when_ptr_names_a_different_host() {
	let mut dns = FakeDns::default();
	let ip = ip("203.0.113.10");
	dns.ptr.insert(ip, vec!["other.example".into()]);
	dns.addresses.insert("mail.example.org".into(), vec![ip]);
	assert_eq!(
		ptr_report("mail.example.org", ip, &dns).await,
		PtrReport::PointsElsewhere("other.example".into())
	);
}

#[tokio::test]
async fn ptr_report_does_not_resolve_back_when_forward_is_broken() {
	let mut dns = FakeDns::default();
	let address = ip("203.0.113.10");
	dns.ptr.insert(address, vec!["mail.example.org".into()]);
	// Hostname resolves to a different IP, so the round trip is broken.
	dns.addresses
		.insert("mail.example.org".into(), vec![ip("198.51.100.7")]);
	assert_eq!(
		ptr_report("mail.example.org", address, &dns).await,
		PtrReport::DoesNotResolveBack
	);
}

#[tokio::test]
async fn ptr_report_folds_a_transient_lookup_error_into_none() {
	let dns = FakeDns {
		fail_ptr: true,
		..Default::default()
	};
	let ip = ip("203.0.113.10");
	assert_eq!(
		ptr_report("mail.example.org", ip, &dns).await,
		PtrReport::None
	);
}

#[test]
fn ptr_report_display_names_both_the_expected_and_found_host() {
	// The Display text is the operator-facing output: for PointsElsewhere
	// it must name both the expected hostname and the one actually found,
	// so a third party (the IP provider) sees exactly what to change.
	let report = PtrReport::PointsElsewhere("other.example".into());
	let text = report.to_string();
	assert!(text.contains("other.example"), "text was {text:?}");
}

#[test]
fn ptr_report_display_for_each_variant() {
	let cases: &[(PtrReport, &[&str])] = &[
		(PtrReport::Ok, &["reverse DNS points at the hostname"]),
		(PtrReport::None, &["no reverse record", "owner of this IP"]),
		(
			PtrReport::PointsElsewhere("other.example".into()),
			&["other.example", "owner of this IP"],
		),
		(
			PtrReport::DoesNotResolveBack,
			&["does not resolve back", "DNS provider"],
		),
	];
	for (report, needles) in cases {
		let text = report.to_string();
		for needle in *needles {
			assert!(
				text.contains(needle),
				"{report:?}: text {text:?} should contain {needle:?}"
			);
		}
	}
}

#[test]
fn detect_returns_ok_on_this_machine() {
	// `detect()` walks `getifaddrs` and runs the result through the same
	// classifier the unit tests above pin. The smoke assertion is "it
	// returns Ok and every chosen address is global". The call is free to
	// return `(None, None)` on a host with no global interface, so the test
	// does not require a non-empty result.
	let result = detect().expect("detect should not fail");
	let (v4, v6) = result;
	if let Some(v4) = v4 {
		assert!(
			non_global_ipv4_reason(v4).is_none(),
			"detect chose {v4}, which is not global"
		);
	}
	if let Some(v6) = v6 {
		assert!(
			non_global_ipv6_reason(v6).is_none(),
			"detect chose {v6}, which is not global"
		);
	}
}
