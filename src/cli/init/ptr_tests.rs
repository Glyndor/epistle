//! The reverse-DNS block against the shared fake resolver: one line per
//! outcome, both addresses in one block, and no block without addresses.

use std::net::IpAddr;

use super::*;
use crate::cli::status::dns_fake::FakeDns;

const HOST: &str = "mail.example.org";
const HEADER: &str = "reverse DNS (PTR), expected to name mail.example.org:\n";

fn v4() -> IpAddr {
	"8.8.8.8".parse().expect("v4")
}

fn v6() -> IpAddr {
	"2606:4700::1111".parse().expect("v6")
}

fn block(addresses: &[IpAddr], dns: Option<&dyn DnsLookup>) -> String {
	let mut out = Vec::new();
	render(HOST, addresses, dns, &mut out);
	String::from_utf8(out).expect("utf-8")
}

/// A PTR for `address` naming `name`, with the hostname resolving to
/// `forward`.
fn published(address: IpAddr, name: &str, forward: &[IpAddr]) -> FakeDns {
	let mut dns = FakeDns::default();
	dns.ptr.insert(address, vec![name.to_string()]);
	dns.addresses.insert(HOST.to_string(), forward.to_vec());
	dns
}

#[test]
fn a_forward_confirmed_ptr_matches() {
	let dns = published(v4(), HOST, &[v4()]);
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!("{HEADER}  8.8.8.8: ok, points at {HOST}, which resolves back to it\n")
	);
}

#[test]
fn a_ptr_naming_another_host_points_elsewhere() {
	let dns = published(v4(), "dns.google", &[v4()]);
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!(
			"{HEADER}  8.8.8.8: points at dns.google; ask your hosting provider to change the PTR of 8.8.8.8 to {HOST}\n"
		)
	);
}

#[test]
fn an_address_without_ptr_is_missing() {
	let dns = FakeDns::default();
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!(
			"{HEADER}  8.8.8.8: missing; ask your hosting provider to set the PTR of 8.8.8.8 to {HOST}\n"
		)
	);
}

#[test]
fn a_failed_ptr_query_is_a_lookup_failure() {
	let mut dns = published(v4(), HOST, &[v4()]);
	dns.ptr_errors.push(v4());
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!("{HEADER}  8.8.8.8: lookup failed; check again later with `epistle verify-dns`\n")
	);
}

#[test]
fn a_ptr_whose_name_does_not_resolve_back_is_not_a_match() {
	let other: IpAddr = "1.1.1.1".parse().expect("v4");
	let dns = published(v4(), HOST, &[other]);
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!(
			"{HEADER}  8.8.8.8: points at {HOST}, but {HOST} does not resolve to 8.8.8.8; publish the A record for {HOST} in its zone\n"
		)
	);
}

#[test]
fn both_addresses_share_one_block() {
	let mut dns = published(v4(), HOST, &[v4(), v6()]);
	dns.ptr.insert(v6(), vec!["one.one.one.one".to_string()]);
	assert_eq!(
		block(&[v4(), v6()], Some(&dns)),
		format!(
			"{HEADER}  8.8.8.8: ok, points at {HOST}, which resolves back to it\n  \
			 2606:4700::1111: points at one.one.one.one; ask your hosting provider to change the PTR of 2606:4700::1111 to {HOST}\n"
		)
	);
}

#[test]
fn no_address_means_no_block() {
	let dns = FakeDns::default();
	assert_eq!(block(&[], Some(&dns)), "");
	assert_eq!(block(&[], None), "");
}

#[test]
fn without_a_resolver_every_lookup_failed() {
	assert_eq!(
		block(&[v4(), v6()], None),
		format!(
			"{HEADER}  8.8.8.8: lookup failed; check again later with `epistle verify-dns`\n  \
			 2606:4700::1111: lookup failed; check again later with `epistle verify-dns`\n"
		)
	);
}

#[tokio::test(flavor = "multi_thread")]
async fn inside_a_multi_thread_runtime_the_running_one_is_borrowed() {
	let dns = published(v4(), HOST, &[v4()]);
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!("{HEADER}  8.8.8.8: ok, points at {HOST}, which resolves back to it\n")
	);
}

#[tokio::test(flavor = "current_thread")]
async fn inside_a_current_thread_runtime_the_lookup_is_reported_failed() {
	let dns = published(v4(), HOST, &[v4()]);
	assert_eq!(
		block(&[v4()], Some(&dns)),
		format!("{HEADER}  8.8.8.8: lookup failed; check again later with `epistle verify-dns`\n")
	);
}
