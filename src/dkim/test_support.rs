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
pub(crate) const GOLDEN_PLAIN: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tY0FHfygsQZI4RmiaoK4BcGUfJ98ZUuCgqseoPw1+QVkPr03kzoTGSjAhh9vk/Sm7\r\n\tHpE5ozu53cVIMvyq+P23BA==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tgX1dGmN/pmFOUP5mHd63HTjzh9/9lteSGydzgYag0BedNqpGQfRRy1UwWk4Ee9g5\r\n\tnB3R/tvh+1wzkIyKBTsdge+erbwVrni42HCHhcYn+nNQXZXqja9Ct2JCnoduVk08\r\n\tTpf7z2KFRrkGWLBwKteM1H3uL33wd7mK+I81gmcj9hc8ecMMR3FwYtKGR5hmmew1\r\n\twqFAcmZ6/fKHrZrGjL7nbbJsfNZahFXXNi/HsqWMXOBZHFhsjevQhVlrQhQfzJVi\r\n\t84MJYpaqQtvuc3vU3uYtArITg3mBAtOOOMHhk1EhPNWEKA464um521pIcpyIM0JI\r\n\tggpoqNB9bmwkZ334b6TWKA==\r\n";

pub(crate) const GOLDEN_FOLDED: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\tbjamRigR54ORH3+1fDHb7J2ZD3h442KUh02LhxQ+YL3qAOGo66GmzPeFDcEL7Tfq\r\n\tqkkwiVLBDbjH0RPHqd0VDw==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:message-id:\r\n\tlist-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\thqi1ltugwiwaymuTIWCbg57OivpjAVMnzRbnlmOCuwsuU2LI3zkI4ZcB3+CNyKRJ\r\n\tfF4z3dzYk4TNrQFe0rsGoxK8wcwq/TlbitKrT0YwyYNPyrLpDJgxOsQ6Hvxqqf+t\r\n\tfQglD+X4ydcyUHGhtR2c8KCUYCQfjmuIqwKmU3FFMW5U72OKg0DE/Nkp/oiHtl5Q\r\n\tYeBiCCTc3mZMzy4ngVhcGtUfZqsjkNNqhCUTwNOtpZkvNs12mpyfmHI4KCVX17Of\r\n\txwuENPKAxB3ZLRe5+fbpW7n/G5khyricyosdnLfr1lv5aNpZKEaRrBm5Hxm4rwwD\r\n\tnumomxeS+0cSrD2LxBLORQ==\r\n";

pub(crate) const GOLDEN: [(&str, &str); 2] = [(PLAIN, GOLDEN_PLAIN), (FOLDED, GOLDEN_FOLDED)];
