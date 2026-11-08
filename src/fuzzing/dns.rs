//! The DNS adapters: the records a domain publishes and the reports it sends.

use super::common::INPUT_CAP;
use super::common::floor_char_boundary;

/// The records a sending domain publishes and the server reads before it
/// delivers: the MTA-STS policy file, the TLS-RPT record and a TLSA record in
/// its presentation form.
pub fn dns_security_records(text: &str) {
	let text = &text[..floor_char_boundary(text, INPUT_CAP)];
	let _ = crate::mtasts::parse_policy(text);
	std::hint::black_box(crate::tlsrpt::parse(text));
	std::hint::black_box(crate::dane::tlsa::TlsaRecord::parse_presentation(text));
}

/// A DMARC or TLS-RPT report as a remote reporter sends it: the XML and the
/// JSON parsers and the three ways an attachment is unpacked.
pub fn report_payload(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let _ = crate::reports::dmarc::parse(raw);
	let _ = crate::reports::tlsrpt::parse(raw);
	for encoding in [
		crate::reports::Encoding::Gzip,
		crate::reports::Encoding::Zip,
		crate::reports::Encoding::Uncompressed,
	] {
		let _ = crate::reports::inflate_attachment(raw, encoding);
	}
}

/// The records a sender publishes for the checks on inbound mail: an SPF
/// record, a DMARC record and a DKIM key record, read from the same text.
/// The first line is the envelope sender and the second the HELO name, cut to
/// an SMTP command line: the SPF macros expand both, so the local part is the
/// attacker's too. Every domain an SPF record names is expanded, as the
/// evaluator does before it looks the name up.
pub fn sender_auth_records(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	let mut lines = input.splitn(3, '\n');
	let sender = smtp_line(lines.next().unwrap_or(""));
	let helo = smtp_line(lines.next().unwrap_or(""));
	let record = lines.next().unwrap_or("");
	if let Ok(spf) = crate::spf::record::parse(record) {
		for (_, mechanism) in &spf.directives {
			use crate::spf::record::Mechanism;
			match mechanism {
				Mechanism::Ip4 { prefix, .. } => assert!(*prefix <= 32, "ip4 prefix /{prefix}"),
				Mechanism::Ip6 { prefix, .. } => assert!(*prefix <= 128, "ip6 prefix /{prefix}"),
				Mechanism::A {
					domain,
					prefix4,
					prefix6,
				}
				| Mechanism::Mx {
					domain,
					prefix4,
					prefix6,
				} => {
					assert!(*prefix4 <= 32 && *prefix6 <= 128, "/{prefix4} //{prefix6}");
					spf_names(domain.as_deref().unwrap_or(SENDER_DOMAIN), sender, helo);
				}
				Mechanism::Include { domain } | Mechanism::Exists { domain } => {
					spf_names(domain, sender, helo);
				}
				Mechanism::Ptr { domain } => {
					spf_names(domain.as_deref().unwrap_or(SENDER_DOMAIN), sender, helo);
				}
				Mechanism::All => {}
			}
		}
		if let Some(redirect) = &spf.redirect {
			spf_names(redirect, sender, helo);
		}
	}
	spf_names(record, sender, helo);
	if let Some(Ok(dmarc)) = crate::dmarc::record::parse(record) {
		assert!(dmarc.pct <= 100, "pct={}", dmarc.pct);
		assert!(dmarc.rua.iter().all(|uri| !uri.is_empty()));
	}
	if let Some(key) = crate::dkim::key_record::parse(record) {
		use crate::dkim::key_record::KeyType;
		match key.key_type {
			KeyType::Ed25519 => assert_eq!(key.public_key.len(), 32),
			KeyType::Rsa => assert_eq!(key.public_key.first(), Some(&0x30)),
		}
		std::hint::black_box(key.accepts_identity(Some(sender), SENDER_DOMAIN));
		assert!(crate::dkim::key_record::same_usable_key(record, record));
	}
	for algorithm in [
		crate::dkim::signature::Algorithm::RsaSha256,
		crate::dkim::signature::Algorithm::Ed25519Sha256,
	] {
		let found = crate::dkim::key_record::select(&[record.to_string()], algorithm);
		assert!(found.is_none_or(|key| key.fits(algorithm)));
	}
}

/// The domain the SPF and DKIM checks of [`sender_auth_records`] run for.
const SENDER_DOMAIN: &str = "example.org";

/// `line` cut where an SMTP command line ends.
fn smtp_line(line: &str) -> &str {
	&line[..floor_char_boundary(line, crate::smtp::command::MAX_COMMAND_LINE)]
}

/// The name an SPF domain spec expands to for a client on each address
/// family. A spec without a macro expands to itself.
fn spf_names(spec: &str, sender: &str, helo: &str) {
	for ip in [
		std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
		std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
	] {
		let name = crate::spf::expand_macro(spec, ip, SENDER_DOMAIN, sender, helo);
		if !spec.contains('%') {
			assert_eq!(name.as_deref().ok(), Some(spec));
		}
		std::hint::black_box(name.map(|name| name.len()).ok());
	}
}
