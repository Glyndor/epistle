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
	for_domains(config, &config.domains)
}

/// Compute the records `config` needs for `domains`, a subset of its hosted
/// domains (`epistle domain add` prints the one it added). It is the same
/// computation as [`from_config`], with the same role and `skip` filter, so
/// the records of one domain are the ones the full set holds for it.
pub fn for_domains(config: &Config, domains: &[String]) -> Result<Desired, Vec<String>> {
	let mut warnings = Vec::new();
	let mut errors = Vec::new();
	let mut dkim_default = Vec::new();
	let mut dkim_per_domain = DomainDkim::new();
	if let Some(dkim) = &config.dkim {
		match default_dkim_pairs(dkim, &config.data_dir, &mut warnings) {
			Ok(pairs) => dkim_default = pairs,
			Err(error) => errors.push(error),
		}
		match per_domain_dkim_pairs(dkim, domains) {
			Ok(map) => dkim_per_domain = map,
			Err(error) => errors.push(error),
		}
	}
	if !errors.is_empty() {
		return Err(errors);
	}
	// The TLSA association names the leaf certificate in service, and only
	// when that certificate is the one that stays in service. The zone has
	// to be one the operator says is signed: that is the
	// `[dns_publish] dane` flag, and the record filter reads it.
	let tlsa = served_association(config, &mut warnings);
	let records = records::build_records_for_roles(
		domains,
		&config.hostname,
		(&dkim_default, &dkim_per_domain),
		(
			tlsa.as_deref(),
			&records::mta_sts_id(config),
			// The SRV locators follow the configuration: a service the
			// operator turned off gets no locator, so a client that follows
			// one of the published records reaches a listener.
			ServiceRecords::from_config(config),
		),
		(
			config.acme.as_ref().map(|a| a.directory_url.as_str()),
			config.public_ipv4,
			config.public_ipv6,
		),
		&config.roles(),
	);
	// The filter lives here, once: the reconcile loop and `epistle dns
	// publish` read this set, so a record the configuration skips is out
	// of both.
	let (records, skipped) = crate::dns::skip::split_records(records, &config.skip_set());
	Ok(Desired {
		records,
		warnings,
		skipped,
	})
}

/// The DANE association of the certificate in service, when that
/// certificate is the one that stays in service.
///
/// The association is the `3 0 1` value of the leaf certificate, hashed
/// (RFC 7672). Two things have to hold for it to be published:
///
/// - The certificate in service has to be the one that stays there. With
///   `[acme]` on, the pair in service is the bootstrap one until the
///   authority answers, and the renewal loop replaces it: a record
///   naming the bootstrap names a certificate the server stops
///   presenting, and every sender that honours DANE refuses the mail.
///   Without `[acme]` the operator's own pair is the one in service.
/// - The zone has to be one the operator says is signed. That is the
///   `[dns_publish] dane` flag, and it is read by the record filter
///   (see [`crate::dns::skip`]), not here.
///
/// A certificate that cannot be read is an input that failed, never "no
/// DANE record needed": the warning marks the set incomplete, so the
/// publisher retires nothing on its strength.
fn served_association(config: &Config, warnings: &mut Vec<String>) -> Option<String> {
	let served = crate::tls::served_tls(config)?;
	if !stays_in_service(config, &served) {
		warnings.push(format!(
			"the certificate in service ({}) is the one the authority replaces at the first \
			 issuance, so the DANE record is not published until the issued certificate is \
			 in service",
			served.tls.cert_file.display()
		));
		return None;
	}
	match std::fs::read_to_string(&served.tls.cert_file) {
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
}

/// Whether the certificate in service is the one that stays in service.
///
/// With `[acme]` on, the pair in service is the issued one only after the
/// authority has answered; before that it is the bootstrap pair, which
/// the renewal loop replaces. Without `[acme]` there is no renewal loop
/// and the operator's own pair is the one in service.
fn stays_in_service(config: &Config, served: &crate::tls::ServedTls) -> bool {
	match &config.acme {
		Some(_) => served.source == crate::tls::CertSource::Acme,
		None => true,
	}
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
/// optional RSA selector adds a second pair. Only the overrides of `domains`
/// are loaded: the key of a domain that is not being computed is not an
/// input of the result.
fn per_domain_dkim_pairs(dkim: &Dkim, domains: &[String]) -> Result<DomainDkim, String> {
	let mut map = DomainDkim::new();
	for entry in dkim
		.domain
		.iter()
		.filter(|entry| domains.iter().any(|d| d.eq_ignore_ascii_case(&entry.name)))
	{
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
