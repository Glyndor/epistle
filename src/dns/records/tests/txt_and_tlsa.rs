//! Tests for TXT string splitting, zone form and the TLSA association.

use super::*;

#[test]
fn a_short_value_is_one_string() {
	assert_eq!(
		txt_strings("v=DKIM1; k=ed25519; p=AAAA"),
		vec!["v=DKIM1; k=ed25519; p=AAAA".to_string()]
	);
}

#[test]
fn a_410_byte_value_splits_into_two_strings_on_a_char_boundary() {
	// Build a value with a multi-byte UTF-8 codepoint straddling the 255-byte
	// cut. `ñ` (U+00F1) encodes as 0xC3 0xB1, two bytes. Position it so
	// the codepoint starts at byte 254 (occupying 254..256) and the cut
	// would land mid-codepoint without the boundary guard.
	let mut fragile_value = String::new();
	fragile_value.push_str(&"A".repeat(254));
	fragile_value.push('\u{00F1}'); // bytes 254..256: straddles byte 255
	fragile_value.push_str(&"A".repeat(200));

	let parts = txt_strings(&fragile_value);
	assert!(parts.len() >= 2, "got {} parts", parts.len());
	for part in &parts {
		assert!(
			part.len() <= 255,
			"string of {} bytes is too long",
			part.len()
		);
		assert!(
			std::str::from_utf8(part.as_bytes()).is_ok(),
			"split mid-character"
		);
	}
	// Joining the parts must reproduce the original, resolvers see one
	// logical TXT record again.
	let joined: String = parts.concat();
	assert_eq!(joined, fragile_value);
}

#[test]
fn zone_form_escapes_quotes_and_backslashes() {
	assert_eq!(txt_zone_form(r#"a"b\c"#), r#""a\"b\\c""#.to_string());
}

/// An octet outside printable ASCII is a `\DDD` decimal escape in zone
/// file syntax (RFC 1035 §5.1); writing each byte as a character turned
/// `é` into `Ã©`.
#[test]
fn zone_form_escapes_non_ascii_octets_in_decimal() {
	assert_eq!(txt_zone_form("café"), r#""caf\195\169""#);
	assert_eq!(txt_zone_form("tab\there"), r#""tab\009here""#);
}

/// The strings of a long value are separated by a space, the way every
/// provider that takes presentation form gets them.
#[test]
fn zone_form_separates_the_strings_of_a_long_value() {
	let value = "a".repeat(300);
	assert_eq!(
		txt_zone_form(&value),
		format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45))
	);
}

#[test]
fn zone_form_wraps_long_values_in_multiple_quoted_strings() {
	let value: String = "a".repeat(600);
	let rendered = txt_zone_form(&value);
	assert!(rendered.starts_with('"'));
	assert!(rendered.ends_with('"'));
	// One quote pair per split string, no character split mid-string.
	let quote_count = rendered.chars().filter(|c| *c == '"').count();
	assert_eq!(quote_count, txt_strings(&value).len() * 2);
}

#[test]
fn tlsa_full_cert_hashes_the_leaf() {
	let cert = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
		.expect("self-signed");
	let pem = cert.cert.pem();
	let assoc = tlsa_full_cert(&pem).expect("association");
	// DANE-EE, full cert, SHA-256: "3 0 1 " + 64 hex chars.
	assert!(
		assoc.starts_with("3 0 1 "),
		"the association must be DANE-EE, full cert, SHA-256"
	);
	let hex = assoc.strip_prefix("3 0 1 ").unwrap();
	assert_eq!(hex.len(), 64, "the digest must be 64 hex characters");
	assert!(
		hex.chars().all(|c| c.is_ascii_hexdigit()),
		"the digest must be hexadecimal"
	);
}

#[test]
fn tlsa_full_cert_rejects_non_pem() {
	assert_eq!(tlsa_full_cert("not a certificate"), None);
	assert_eq!(
		tlsa_full_cert("-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n"),
		None
	);
}

#[tokio::test]
async fn publish_tlsa_upserts_a_3_0_1_record() {
	use crate::dns::provider::{DnsProvider, ProviderError};
	use std::pin::Pin;
	use std::sync::Mutex;

	#[derive(Default)]
	struct Capture(Mutex<Vec<super::PublishRecord>>);
	impl DnsProvider for Capture {
		fn upsert(
			&self,
			zone: &str,
			record: super::DnsRecord,
		) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
			self.0.lock().unwrap().push(super::PublishRecord {
				zone: zone.to_string(),
				record,
			});
			Box::pin(async { Ok(()) })
		}
		fn delete(
			&self,
			_zone: &str,
			_record: super::DnsRecord,
		) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
			Box::pin(async { Ok(()) })
		}
		fn list(
			&self,
			_zone: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<super::DnsRecord>, ProviderError>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	let cert =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()]).expect("cert");
	let provider = Capture::default();
	publish_tlsa(&provider, "mail.example.org", &cert.cert.pem())
		.await
		.expect("publish");
	let captured = provider.0.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0].record.name, "_25._tcp.mail.example.org");
	assert_eq!(captured[0].record.kind, RecordKind::Tlsa);
	assert!(captured[0].record.value.starts_with("3 0 1 "));
}

#[tokio::test]
async fn publish_tlsa_noop_without_certificate() {
	use crate::dns::provider::ManualProvider;
	// No cert in the PEM → nothing to publish, no error.
	publish_tlsa(&ManualProvider, "mail.example.org", "garbage")
		.await
		.expect("noop");
}
