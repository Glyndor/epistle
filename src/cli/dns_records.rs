//! `epistle dns-records`: print the DNS records a deployment should publish
//! (SPF, DKIM, DMARC, MTA-STS, MX and a DANE TLSA record when a certificate is
//! present), for manual entry or to feed a DNS provider. Read-only.

use std::process::ExitCode;

use crate::config::Config;
use crate::dns::provider::RecordKind;
use crate::dns::records::{self, PublishRecord, Services, txt_zone_form};

/// Default MTA-STS policy id; the operator bumps it whenever the policy served
/// over HTTPS changes so resolvers refetch.
const MTA_STS_ID: &str = "epistle1";

/// Compute and print the expected records for the configured domains.
pub(super) fn run(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	// DKIM records from the configured signer: the ed25519 selector always,
	// plus the optional RSA dual-signing selector when both fields are set.
	let dkim_owned: Vec<(String, String)> = config
		.dkim
		.as_ref()
		.map(|dkim| {
			let mut pairs = Vec::new();
			match crate::dkim::Signer::load(&dkim.selector, &dkim.key_file) {
				Ok(signer) => {
					pairs.push((dkim.selector.clone(), signer.dns_record_value()));
					if let (Some(rsa_selector), Some(rsa_key_file)) =
						(dkim.rsa_selector.as_ref(), dkim.rsa_key_file.as_ref())
					{
						match signer.with_rsa(rsa_selector, rsa_key_file) {
							Ok(with_rsa) => {
								if let Some(value) = with_rsa.rsa_dns_record_value() {
									pairs.push((rsa_selector.clone(), value));
								}
							}
							Err(error) => {
								eprintln!("warning: cannot load RSA DKIM key: {error}");
							}
						}
					}
				}
				Err(error) => {
					eprintln!("warning: cannot load DKIM key: {error}");
				}
			}
			pairs
		})
		.unwrap_or_default();

	// TLSA association from the leaf certificate, if a cert is configured.
	let tlsa = config
		.tls
		.as_ref()
		.and_then(|tls| match std::fs::read_to_string(&tls.cert_file) {
			Ok(pem) => records::tlsa_full_cert(&pem),
			Err(error) => {
				eprintln!("warning: cannot read certificate: {error}");
				None
			}
		});

	let recs = records::build_records(
		&config.domains,
		&config.hostname,
		&dkim_owned,
		tlsa.as_deref(),
		MTA_STS_ID,
		// The `webdav` listener always exposes CalDAV/CardDAV when present;
		// we don't have a flag for "operator disabled CalDAV only", so emit
		// both SRVs and let the operator prune them by hand if needed.
		Services::all(),
		config.acme.as_ref().map(|a| a.directory_url.as_str()),
	);
	report(&recs, out)
}

/// Print one line per record: `name TTL IN KIND value`. TXT values are
/// rendered through [`txt_zone_form`] so values longer than 255 octets split
/// into the quoted, RFC 1035 §3.3.14 string form a zone file accepts.
fn report(records: &[PublishRecord], out: &mut impl std::io::Write) -> ExitCode {
	for entry in records {
		let r = &entry.record;
		let value = match r.kind {
			RecordKind::Txt => txt_zone_form(&r.value),
			_ => r.value.clone(),
		};
		if writeln!(out, "{} {} IN {} {}", r.name, r.ttl, r.kind.as_str(), value).is_err() {
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dns::provider::{DnsRecord, RecordKind};

	#[test]
	fn report_prints_zone_file_lines() {
		let records = vec![PublishRecord {
			zone: "example.org".to_string(),
			record: DnsRecord {
				name: "_dmarc.example.org".to_string(),
				kind: RecordKind::Txt,
				value: "v=DMARC1; p=none".to_string(),
				ttl: 3600,
			},
		}];
		let mut out = Vec::new();
		assert_eq!(report(&records, &mut out), ExitCode::SUCCESS);
		let text = String::from_utf8(out).expect("utf8");
		assert_eq!(
			text,
			"_dmarc.example.org 3600 IN TXT \"v=DMARC1; p=none\"\n"
		);
	}

	#[test]
	fn report_splits_a_long_txt_into_quoted_strings() {
		let records = vec![PublishRecord {
			zone: "example.org".to_string(),
			record: DnsRecord {
				name: "rsasel._domainkey.example.org".to_string(),
				kind: RecordKind::Txt,
				value: "v=DKIM1; k=rsa; p=".to_string() + &"A".repeat(600),
				ttl: 3600,
			},
		}];
		let mut out = Vec::new();
		assert_eq!(report(&records, &mut out), ExitCode::SUCCESS);
		let text = String::from_utf8(out).expect("utf8");
		// A 614-byte value splits into 3 strings of ≤255 bytes → 6 quotes.
		let quote_count = text.chars().filter(|c| *c == '"').count();
		assert!(quote_count >= 6, "got {quote_count} quotes in {text}");
	}
}
