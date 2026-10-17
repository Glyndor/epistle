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

/// Whether the RSA `DKIM-Signature` header `line` (without CRLF) verifies
/// over `raw` with the public key in the TXT `record`. Checked here rather
/// than through `verify_message`, whose RSA path is not under test.
pub(crate) fn rsa_verifies(line: &str, record: &str, raw: &[u8]) -> bool {
	use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};

	let value = line.strip_prefix("DKIM-Signature:").expect("RSA header");
	let signature = super::signature::parse(value).expect("parse RSA signature");
	let Some(spki) = super::parse_key(record) else {
		return false;
	};
	let Ok((_, public)) = SubjectPublicKeyInfo::from_der(&spki) else {
		return false;
	};
	let raw = std::str::from_utf8(raw).expect("UTF-8 message");
	let (headers, body) = raw.split_once("\r\n\r\n").expect("message sections");
	let body = super::canon::body(signature.body_canon, body.as_bytes());
	if signature.body_hash != ring::digest::digest(&ring::digest::SHA256, &body).as_ref() {
		return false;
	}
	let mut input = String::new();
	for name in signature.signed_headers {
		let (name, value) = headers
			.lines()
			.filter_map(|line| line.split_once(':'))
			.find(|(field, _)| field.eq_ignore_ascii_case(&name))
			.expect("signed header");
		input.push_str(&super::canon::header(signature.header_canon, name, value));
	}
	let unsigned = format!("{}b=", value.rsplit_once("b=").expect("signature value").0);
	let canonical = super::canon::header(signature.header_canon, "DKIM-Signature", &unsigned);
	input.push_str(canonical.strip_suffix("\r\n").expect("canonical CRLF"));
	ring::signature::UnparsedPublicKey::new(
		&ring::signature::RSA_PKCS1_2048_8192_SHA256,
		public.subject_public_key.data.as_ref(),
	)
	.verify(input.as_bytes(), &signature.signature)
	.is_ok()
}
