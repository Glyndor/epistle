//! The record set a configuration needs in DNS, computed in one place.
//!
//! `epistle dns-records` prints this set and the publisher compares it with
//! the zone, so what an operator reads is what a provider receives. The inputs are read
//! here: the DKIM keys through the signer and the rotation state, the TLSA
//! association from the certificate in service, the MTA-STS policy id and the
//! services the listeners enable. [`crate::dns::records::build_records`] turns
//! them into records.

use std::path::Path;

use crate::config::{Config, Dkim};
use crate::dns::records::{self, DomainDkim, PublishRecord, ServiceRecords};
use crate::dns::skip::SkippedGroup;

/// The records a configuration needs, and what could not be read while
/// computing them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
	/// Every record, in the order [`records::build_records`] emits them.
	pub records: Vec<PublishRecord>,
	/// Inputs that could not be read and were left out (a DKIM key file
	/// that does not load, a certificate that cannot be read or holds no
	/// certificate). The set can still be printed and its records created,
	/// but it is incomplete: see [`Desired::incomplete`].
	pub warnings: Vec<String>,
	/// The groups the configuration skips, and the records they hold. They
	/// are not in [`Desired::records`]: the wanted set is what epistle
	/// publishes.
	pub skipped: Vec<SkippedGroup>,
}

impl Desired {
	/// Why the set is incomplete, when an input could not be read. A record
	/// missing from an incomplete set is not a record the configuration no
	/// longer needs, so a publisher must not retire anything on its strength.
	pub fn incomplete(&self) -> Option<String> {
		(!self.warnings.is_empty()).then(|| self.warnings.join("; "))
	}
}

/// Compute the records `config` needs.
///
/// An input that makes the whole set wrong is an error: a rotation state
/// that cannot be read would otherwise publish the configured selector
/// instead of the one in service, and a per-domain key that does not load
/// would publish the default key for a domain that does not sign with it.
/// Every error found is returned, not only the first.
pub fn from_config(config: &Config) -> Result<Desired, Vec<String>> {
	let mut warnings = Vec::new();
	let mut errors = Vec::new();
	let mut dkim_default = Vec::new();
	let mut dkim_per_domain = DomainDkim::new();
	if let Some(dkim) = &config.dkim {
		match default_dkim_pairs(dkim, &config.data_dir, &mut warnings) {
			Ok(pairs) => dkim_default = pairs,
			Err(error) => errors.push(error),
		}
		match per_domain_dkim_pairs(dkim) {
			Ok(map) => dkim_per_domain = map,
			Err(error) => errors.push(error),
		}
	}
	if !errors.is_empty() {
		return Err(errors);
	}
	// The TLSA association names the leaf certificate in service: the
	// pair the authority issued when there is one, the `[tls]` pair
	// otherwise. It is not always the one `[tls]` names.
	let tlsa = crate::tls::served_tls(config).as_ref().and_then(|served| {
		match std::fs::read_to_string(&served.tls.cert_file) {
			// A certificate in service is expected to give a TLSA record:
			// a file without one is an input that failed, never "no TLSA
			// needed", or the publisher would retire the record it wrote.
			Ok(pem) => records::tlsa_full_cert(&pem).or_else(|| {
				warnings.push(format!(
					"{} holds no certificate, so the TLSA record cannot be computed",
					served.tls.cert_file.display()
				));
				None
			}),
			Err(error) => {
				warnings.push(format!("cannot read certificate: {error}"));
				None
			}
		}
	});
	let records = records::build_records(
		&config.domains,
		&config.hostname,
		&dkim_default,
		&dkim_per_domain,
		tlsa.as_deref(),
		&records::mta_sts_id(config),
		// The SRV locators follow the configuration: a service the
		// operator turned off gets no locator, so a client that follows
		// one of the published records reaches a listener.
		ServiceRecords::from_config(config),
		config.acme.as_ref().map(|a| a.directory_url.as_str()),
		config.public_ipv4,
		config.public_ipv6,
	);
	// The filter lives here, once: the reconcile loop and `epistle dns
	// publish` read this set, so a record the configuration skips is out
	// of both.
	let (records, skipped) =
		crate::dns::skip::split_records(records, &config.dns_publish.skip_set());
	Ok(Desired {
		records,
		warnings,
		skipped,
	})
}

/// The default `[dkim]` selector, and its optional RSA partner, as
/// `(selector, value)` pairs. The rotation state takes precedence over the
/// configured selector when it is readable; a state that cannot be read is
/// an error, never a fallback to the configured selector.
fn default_dkim_pairs(
	dkim: &Dkim,
	data_dir: &Path,
	warnings: &mut Vec<String>,
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
					Err(error) => warnings.push(format!("cannot load RSA DKIM key: {error}")),
				}
			}
		}
		Err(error) => warnings.push(format!("cannot load DKIM key: {error}")),
	}
	Ok(pairs)
}

/// The per-domain DKIM overrides as a domain to `(selector, value)` map.
/// Each override is loaded from the file the configuration names; the
/// optional RSA selector adds a second pair.
fn per_domain_dkim_pairs(dkim: &Dkim) -> Result<DomainDkim, String> {
	let mut map = DomainDkim::new();
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

#[cfg(test)]
mod tests;
