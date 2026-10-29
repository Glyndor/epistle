//! `epistle dns-records`: print the DNS records a deployment should publish
//! (SPF, DKIM, DMARC, MTA-STS, MX and a DANE TLSA record when a certificate is
//! present), for manual entry or to feed a DNS provider. Read-only.

use std::process::ExitCode;

use crate::config::Config;
use crate::dns::provider::RecordKind;
use crate::dns::records::{self, PublishRecord, txt_zone_form};

/// Compute and print the expected records for the configured domains.
/// With `json` the records are one JSON array of `{"name", "ttl", "type",
/// "value"}` objects, the TXT values unsplit.
pub fn run(config: &Config, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	// DKIM records from the configured signer: the ed25519 selector always
	// (the one the rotator currently has in service, or the configured one
	// before the first tick), plus the optional RSA dual-signing selector
	// when both fields are set. A per-domain override replaces the default
	// for the domain it names; every other domain keeps the default.
	let mut failed = false;
	let mut dkim_default: Vec<(String, String)> = Vec::new();
	let mut dkim_per_domain: records::DomainDkim = records::DomainDkim::new();
	if let Some(dkim) = &config.dkim {
		match build_default_dkim_pairs(dkim, &config.data_dir) {
			Ok(pairs) => dkim_default = pairs,
			Err(error) => {
				failed = true;
				super::style::error(format_args!("{error}"));
			}
		}
		dkim_per_domain = match build_per_domain_dkim_pairs(dkim) {
			Ok(map) => map,
			Err(error) => {
				failed = true;
				super::style::error(format_args!("{error}"));
				records::DomainDkim::new()
			}
		};
	}

	if failed {
		return ExitCode::FAILURE;
	}

	// TLSA association from the leaf certificate in service: the
	// pair the authority issued when there is one, the `[tls]` pair
	// otherwise. The record has to name the certificate the listeners
	// present, which is not always the one `[tls]` names.
	let tlsa = crate::tls::served_tls(config).as_ref().and_then(|served| {
		match std::fs::read_to_string(&served.tls.cert_file) {
			Ok(pem) => records::tlsa_full_cert(&pem),
			Err(error) => {
				super::style::warn(format_args!("cannot read certificate: {error}"));
				None
			}
		}
	});

	let recs = records::build_records(
		&config.domains,
		&config.hostname,
		&dkim_default,
		&dkim_per_domain,
		tlsa.as_deref(),
		&records::mta_sts_id(config),
		// The SRV locators follow the configuration: a service the
		// operator turned off gets no locator, so a client that follows
		// one of the published records reaches a listener.
		records::ServiceRecords::from_config(config),
		config.acme.as_ref().map(|a| a.directory_url.as_str()),
		config.public_ipv4,
		config.public_ipv6,
	);
	if json {
		return super::json_out::print(out, &records_json(&recs));
	}
	report(&recs, out)
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

/// The default `[dkim]` selector (and its optional RSA partner) as
/// `(selector, value)` pairs. The rotation state takes precedence over
/// the configured value when the state is readable.
fn build_default_dkim_pairs(
	dkim: &crate::config::Dkim,
	data_dir: &std::path::Path,
) -> Result<Vec<(String, String)>, String> {
	let mut pairs = Vec::new();
	let active =
		crate::dkim::rotate::active_ed25519(dkim, data_dir).map_err(|error| error.to_string())?;
	let ed_selector = active.selector;
	match crate::dkim::Signer::load(&ed_selector, &active.key_file) {
		Ok(signer) => {
			pairs.push((ed_selector, signer.dns_record_value()));
			let rsa = crate::dkim::rotate::active_rsa(dkim, data_dir)
				.ok()
				.flatten();
			if let Some(rsa) = rsa {
				match crate::dkim::rsa_record_value(&rsa.key_file) {
					Ok(value) => pairs.push((rsa.selector, value)),
					Err(error) => {
						super::style::warn(format_args!("cannot load RSA DKIM key: {error}"));
					}
				}
			}
		}
		Err(error) => {
			super::style::warn(format_args!("cannot load DKIM key: {error}"));
		}
	}
	Ok(pairs)
}

/// The per-domain DKIM overrides as a domain -> list of (selector, value)
/// map. Each override is loaded from the file the configuration names;
/// the optional RSA selector adds a second `(selector, value)` pair.
fn build_per_domain_dkim_pairs(dkim: &crate::config::Dkim) -> Result<records::DomainDkim, String> {
	let mut map = records::DomainDkim::new();
	for entry in &dkim.domain {
		let mut pairs = Vec::new();
		let signer = crate::dkim::Signer::load(&entry.selector, &entry.key_file)
			.map_err(|error| error.to_string())?;
		pairs.push((entry.selector.clone(), signer.dns_record_value()));
		if let (Some(rsa_selector), Some(rsa_key_file)) = (&entry.rsa_selector, &entry.rsa_key_file)
		{
			let value =
				crate::dkim::rsa_record_value(rsa_key_file).map_err(|error| error.to_string())?;
			pairs.push((rsa_selector.clone(), value));
		}
		map.insert(entry.name.to_ascii_lowercase(), pairs);
	}
	Ok(map)
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
