//! `epistle dns-records`: print the DNS records a deployment should publish
//! (SPF, DKIM, DMARC, MTA-STS, MX and a DANE TLSA record when a certificate is
//! present), for manual entry or to feed a DNS provider. Read-only.

use std::process::ExitCode;

use crate::config::Config;
use crate::dns::records::{self, PublishRecord};

/// Default MTA-STS policy id; the operator bumps it whenever the policy served
/// over HTTPS changes so resolvers refetch.
const MTA_STS_ID: &str = "epistle1";

/// Compute and print the expected records for the configured domains.
pub(super) fn run(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	// DKIM record value from the configured signer, if any.
	let dkim_owned = config.dkim.as_ref().and_then(|dkim| {
		match crate::dkim::Signer::load(&dkim.selector, &dkim.key_file) {
			Ok(signer) => Some((dkim.selector.clone(), signer.dns_record_value())),
			Err(error) => {
				eprintln!("warning: cannot load DKIM key: {error}");
				None
			}
		}
	});
	let dkim = dkim_owned.as_ref().map(|(s, v)| (s.as_str(), v.as_str()));

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
		dkim,
		tlsa.as_deref(),
		MTA_STS_ID,
	);
	report(&recs, out)
}

/// Print one line per record: `name TTL IN KIND value`.
fn report(records: &[PublishRecord], out: &mut impl std::io::Write) -> ExitCode {
	for entry in records {
		let r = &entry.record;
		if writeln!(
			out,
			"{} {} IN {} {}",
			r.name,
			r.ttl,
			r.kind.as_str(),
			r.value
		)
		.is_err()
		{
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
		assert_eq!(text, "_dmarc.example.org 3600 IN TXT v=DMARC1; p=none\n");
	}
}
