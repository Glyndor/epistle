//! Compute the DNS records epistle expects a deployment to publish: SPF, DKIM,
//! DMARC, MTA-STS, MX and (when a certificate is available) a DANE TLSA record.
//! These pair with [`super::check_domain`] (which verifies them) and can be
//! handed to a [`super::provider::DnsProvider`] to publish, or printed for
//! manual entry.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::provider::{DnsRecord, RecordKind};

/// A record to publish, paired with the zone it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRecord {
	pub zone: String,
	pub record: DnsRecord,
}

const TTL: u32 = 3600;

/// The records to publish for the given domains and mail hostname.
///
/// `dkim` is the `<selector>._domainkey` value (from the loaded signer) when
/// DKIM is configured; `tlsa` is the `3 0 1` association for the mail host's
/// certificate when one is available; `mta_sts_id` versions the MTA-STS record.
pub fn build_records(
	domains: &[String],
	hostname: &str,
	dkim: Option<(&str, &str)>,
	tlsa: Option<&str>,
	mta_sts_id: &str,
) -> Vec<PublishRecord> {
	let mut records = Vec::new();
	for domain in domains {
		let txt = |name: String, value: String| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Txt,
				value,
				ttl: TTL,
			},
		};

		// SPF: authorize the domain's MX hosts; soft-fail the rest.
		records.push(txt(domain.clone(), "v=spf1 mx ~all".to_string()));
		// DMARC: a protective default that reports to postmaster.
		records.push(txt(
			format!("_dmarc.{domain}"),
			format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s"),
		));
		// MTA-STS discovery record (the policy itself is served over HTTPS).
		records.push(txt(
			format!("_mta-sts.{domain}"),
			format!("v=STSv1; id={mta_sts_id}"),
		));
		// MX → the mail hostname at the standard priority.
		records.push(PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name: domain.clone(),
				kind: RecordKind::Mx,
				value: format!("10 {hostname}"),
				ttl: TTL,
			},
		});
		// DKIM public key, if configured.
		if let Some((selector, value)) = dkim {
			records.push(txt(
				format!("{selector}._domainkey.{domain}"),
				value.to_string(),
			));
		}
	}

	// One TLSA record for the mail host (shared across all domains).
	if let Some(association) = tlsa {
		records.push(PublishRecord {
			zone: hostname.to_string(),
			record: DnsRecord {
				name: format!("_25._tcp.{hostname}"),
				kind: RecordKind::Tlsa,
				value: association.to_string(),
				ttl: TTL,
			},
		});
	}

	records
}

/// Build a DANE-EE `3 0 1` TLSA association (SHA-256 of the full certificate)
/// from a PEM chain — the leaf is the first CERTIFICATE block. Returns `None`
/// if no certificate is found. `3 0 1` needs no X.509 parsing, only the DER.
pub fn tlsa_full_cert(cert_pem: &str) -> Option<String> {
	let der = first_certificate_der(cert_pem)?;
	let digest = ring::digest::digest(&ring::digest::SHA256, &der);
	let hex = digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	});
	Some(format!("3 0 1 {hex}"))
}

/// Decode the first PEM `CERTIFICATE` block to DER.
fn first_certificate_der(pem: &str) -> Option<Vec<u8>> {
	const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
	const END: &str = "-----END CERTIFICATE-----";
	let start = pem.find(BEGIN)? + BEGIN.len();
	let end = pem[start..].find(END)? + start;
	let body: String = pem[start..end].split_whitespace().collect();
	BASE64.decode(body).ok()
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;
