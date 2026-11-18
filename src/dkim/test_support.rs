//! In-memory DNS, field checks and fixed keys for signing tests.

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

/// The PKCS#8 v2 envelope of an ed25519 key, around the seed and the public
/// key, the way `Ed25519KeyPair::generate_pkcs8` writes it.
pub(crate) fn ed25519_pem(seed: [u8; 32]) -> String {
	let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
	let mut der = vec![
		0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
		0x20,
	];
	der.extend_from_slice(&seed);
	der.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
	der.extend_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
	super::sign::pem_encode(&der)
}

/// A signer whose keys never change: an ed25519 key from a fixed seed and
/// the committed RSA test key.
pub(crate) fn fixed_signer(dir: &std::path::Path) -> super::Signer {
	let ed = dir.join("ed.pem");
	std::fs::write(&ed, ed25519_pem([7; 32])).expect("write ed25519 key");
	let rsa = dir.join("rsa.pem");
	std::fs::write(&rsa, include_str!("test_rsa_key.pem")).expect("write RSA key");
	super::Signer::load("sel", &ed)
		.expect("load ed25519")
		.with_rsa("rsasel", &rsa)
		.expect("load RSA")
}

pub(crate) const PLAIN: &str = "From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: hello\r\nDate: Fri, 13 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\nX-Other: kept out\r\n\r\nBody line\r\n\r\n\r\n";

pub(crate) const FOLDED: &str = "Resent-From: relay@example.org\r\nResent-Bad;Name: x\r\nSubject: a\r\n folded \t value\r\nFrom: alice@example.org\r\nCC: Carol\r\n <carol@example.net>\r\n\r\nbody\nwith bare line feeds\n";

/// What the signer wrote for [`PLAIN`] and [`FOLDED`] before it was split
/// into halves, captured from `develop` at 30a2235f. Both algorithms are deterministic, so a change here is a
/// change of what receivers verify.
pub(crate) const GOLDEN_PLAIN: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted:\r\n\tx-auto-response-suppress; bh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tFiT6rqlmcCHZUzMhqlGt4OgaE17mmRrPJ4K+d7DPUthAQkFPbholRyjGbuH1C+1f\r\n\tYmiz8KjvN40uyDW+5KcoDg==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted:\r\n\tx-auto-response-suppress; bh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tdQc3POgXeDeyhfrf7w5Cosy0NPya3gfuE6Ieo9YWMK4rIpzTS99zmWoPSFn4FSNT\r\n\txB4ivorllp6NV0uzJTNwcZLwcLmK0npxusUpMmx1zpTgOZUU/Bh891hB39v6mFm3\r\n\t8vthD3VrxAv9mdrSmGXvp7yBuZm9XVpOpQ2lU9I7VmOFrRCVoCjvBU+AuzCNGVnC\r\n\tD25QxzqeJt+1RxSOcETEAYk7oNlQ0Xv8uZ1xSG46WGlzMUZ4P9g/6O3dVMM9+N7h\r\n\tkW6StTGxMSkCoxwC2pK5txVWtGyDBfzf/WMzyEwJFkHfStWHxszoVeg3bvxfUojo\r\n\tmqFePDPaq4SSeeRGiMYHsg==\r\n";

pub(crate) const GOLDEN_FOLDED: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted:\r\n\tx-auto-response-suppress; bh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\t6AYOnDfZGsIwsp5SPolvsDcYCfAlentghYPKCSLJI8/LR9OvpDYj0iKBv2mO6Af+\r\n\tJuwGMTGsy/hDI+nDydxSCQ==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:message-id:\r\n\tlist-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted:\r\n\tx-auto-response-suppress; bh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\taSfA+6E6cXrAY4s7mgLyNF92D+w3Mh76ty16mB9irYoWH7URXOnN9TChEwKrDXNS\r\n\tDlDEOjh34NKcfvElvJEWjU9XxGhC2tSoiDSfBZQaQCizmPpfRvYmCe8iOm0gHo8I\r\n\tjIw4jQnlaP78A/REdoamDcdp+ifHxs8BsGt+aryxYKBXNJfYSmgenefjl+OLXay8\r\n\tdgad/srrKmvNGJJdf4Vfai3uVO49EJ9q4INect+kdzzmsjtZvpQ5eZlGWWSXSBY6\r\n\tK8BPFiii8Y2xb5XBXSW9PY142JPfGwCPzcWGuyZfwSYCCsYZgMD3zzLkW2yetWID\r\n\tei2kMkLLCROrxWnJWvmIXQ==\r\n";

pub(crate) const GOLDEN: [(&str, &str); 2] = [(PLAIN, GOLDEN_PLAIN), (FOLDED, GOLDEN_FOLDED)];
