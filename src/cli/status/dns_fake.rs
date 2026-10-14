//! A resolver with canned answers for the DNS check tests, shared by the
//! `status` DNS area and the reverse-DNS block of `init`.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::spf::{DnsFailure, DnsLookup};

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

#[derive(Default)]
pub(crate) struct FakeDns {
	pub(crate) txt: HashMap<String, Vec<String>>,
	pub(crate) mx: HashMap<String, Vec<String>>,
	pub(crate) addresses: HashMap<String, Vec<IpAddr>>,
	pub(crate) ptr: HashMap<IpAddr, Vec<String>>,
	/// Names whose TXT lookup fails temporarily.
	pub(crate) txt_errors: Vec<String>,
	/// Addresses whose PTR lookup fails temporarily.
	pub(crate) ptr_errors: Vec<IpAddr>,
	/// TLSA RRsets by owner name; absent names have none.
	pub(crate) tlsa: HashMap<String, crate::dane::rrset::TlsaRrset>,
}

impl FakeDns {
	/// Publish everything a healthy `example.org` / `mail.example.org` needs,
	/// except DKIM.
	pub(crate) fn healthy() -> Self {
		let mut dns = FakeDns::default();
		dns.mx
			.insert("example.org".into(), vec!["mail.example.org".into()]);
		dns.txt
			.insert("example.org".into(), vec!["v=spf1 mx -all".into()]);
		dns.txt
			.insert("_dmarc.example.org".into(), vec!["v=DMARC1; p=none".into()]);
		dns.txt
			.insert("_mta-sts.example.org".into(), vec!["v=STSv1; id=1".into()]);
		let ip: IpAddr = "203.0.113.10".parse().expect("ip");
		dns.addresses.insert("mail.example.org".into(), vec![ip]);
		dns.ptr.insert(ip, vec!["mail.example.org".into()]);
		dns
	}
}

impl DnsLookup for FakeDns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let failed = self.txt_errors.iter().any(|n| n == name);
		let found = self.txt.get(name).cloned().unwrap_or_default();
		Box::pin(async move {
			if failed {
				Err(DnsFailure::Temporary)
			} else {
				Ok(found)
			}
		})
	}
	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>> {
		let found = self.addresses.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(found) })
	}
	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let found = self.mx.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(found) })
	}
	fn ptr(&self, ip: IpAddr) -> Lookup<'_, Vec<String>> {
		let failed = self.ptr_errors.contains(&ip);
		let found = self.ptr.get(&ip).cloned().unwrap_or_default();
		Box::pin(async move {
			if failed {
				Err(DnsFailure::Temporary)
			} else {
				Ok(found)
			}
		})
	}
	fn tlsa(&self, name: &str) -> Lookup<'_, crate::dane::rrset::TlsaRrset> {
		let found = self.tlsa.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(found) })
	}
}
