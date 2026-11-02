//! `epistle dns-records`: print the DNS records a deployment should publish
//! (SPF, DKIM, DMARC, MTA-STS, MX and a DANE TLSA record when a certificate is
//! present), for manual entry or to feed a DNS provider. Read-only.

use std::process::ExitCode;

use crate::config::Config;
use crate::dns::provider::RecordKind;
use crate::dns::records::{PublishRecord, txt_zone_form};

/// Compute and print the expected records for the configured domains.
/// With `json` the records are one JSON array of `{"name", "ttl", "type",
/// "value"}` objects, the TXT values unsplit. The set is
/// [`crate::dns::desired::from_config`], computed in one place so that
/// what is printed and what is published cannot drift apart.
pub fn run(config: &Config, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	let desired = match crate::dns::desired::from_config(config) {
		Ok(desired) => desired,
		Err(errors) => {
			for error in errors {
				super::style::error(format_args!("{error}"));
			}
			return ExitCode::FAILURE;
		}
	};
	for warning in &desired.warnings {
		super::style::warn(format_args!("{warning}"));
	}
	if json {
		return super::json_out::print(out, &records_json(&desired.records));
	}
	report(&desired.records, out)
}

/// The records as the JSON array `--json` prints.
pub fn records_json(records: &[PublishRecord]) -> serde_json::Value {
	records
		.iter()
		.map(|entry| {
			let record = &entry.record;
			serde_json::json!({
				"name": record.name, "ttl": record.ttl,
				"type": record.kind.as_str(), "value": record.value,
			})
		})
		.collect()
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
mod tests;
