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

/// Complete signature fields, including their continuation lines and trailing CRLF.
pub(crate) fn signature_headers(raw: &[u8]) -> Vec<String> {
	let text = std::str::from_utf8(raw).expect("message is UTF-8");
	let mut fields: Vec<String> = Vec::new();
	let mut in_signature = false;
	for line in text.split_inclusive("\r\n") {
		if line == "\r\n" {
			break;
		}
		if !line.starts_with([' ', '\t']) {
			in_signature = line.starts_with("DKIM-Signature:");
			if in_signature {
				fields.push(String::new());
			}
		}
		if in_signature {
			fields.last_mut().expect("signature field").push_str(line);
		}
	}
	fields
}

pub(crate) fn signature_fields(raw: &[u8]) -> Vec<(String, String, String)> {
	signature_headers(raw)
		.iter()
		.filter_map(|line| line.strip_prefix("DKIM-Signature:"))
		.map(|line| {
			let tag = |name: &str| {
				line.split(';')
					.filter_map(|field| field.trim().split_once('='))
					.find(|(key, _)| *key == name)
					.expect("signature tag exists")
					.1
					.trim()
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
	let Some(parsed) = super::key_record::parse(record) else {
		return false;
	};
	let spki = parsed.public_key;
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
	let mut fields: Vec<_> = headers
		.lines()
		.filter_map(|line| line.split_once(':'))
		.map(Some)
		.collect();
	for name in signature.signed_headers {
		if let Some(field) = fields.iter_mut().rev().find(|field| {
			field.is_some_and(|(header_name, _)| header_name.eq_ignore_ascii_case(&name))
		}) {
			let (name, value) = field.take().expect("unused header");
			input.push_str(&super::canon::header(signature.header_canon, name, value));
		}
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

/// A resolver whose every TXT lookup fails.
pub(crate) struct FailingDns;

impl DnsLookup for FailingDns {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Err(DnsFailure::Temporary) })
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
