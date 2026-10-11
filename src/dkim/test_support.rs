//! In-memory DNS and field checks for signing lifecycle tests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

use crate::spf::{DnsFailure, DnsLookup};

pub(crate) struct KeyDns(pub HashMap<String, Vec<String>>);

impl DnsLookup for KeyDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let records = self.0.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(records) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

pub(crate) fn signature_fields(raw: &[u8]) -> Vec<(String, String, String)> {
	let text = std::str::from_utf8(raw).expect("message is UTF-8");
	text.split("\r\n\r\n")
		.next()
		.expect("header block")
		.lines()
		.filter_map(|line| line.strip_prefix("DKIM-Signature:"))
		.map(|line| {
			let tag = |name: &str| {
				line.split(';')
					.filter_map(|field| field.trim().split_once('='))
					.find(|(key, _)| *key == name)
					.expect("signature tag exists")
					.1
					.to_string()
			};
			(tag("s"), tag("d"), tag("a"))
		})
		.collect()
}
