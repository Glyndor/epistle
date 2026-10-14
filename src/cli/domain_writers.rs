//! `epistle domain`: low-level helpers that emit DNS records and the
//! shared commit/restart policy. Lives in a sibling so `domain.rs`
//! stays under the per-file code-line budget.

use std::io::Write;
use std::process::ExitCode;

use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;

use crate::dns::provider::RecordKind;
use crate::dns::records as dns_records;

/// Print the DNS records `dns-records` would emit, restricted to one
/// domain. Mirrors `crate::cli::dns_records::run` so the operator sees
/// the same shape they would on a full run.
pub fn print_domain_records(
	config: &Config,
	domain: &str,
	out: &mut impl Write,
) -> std::io::Result<()> {
	// One domain is printed, so its own key (a `[[dkim.domain]]` override
	// when it has one, the `[dkim]` default otherwise) is the only one.
	let mut dkim_owned: Vec<(String, String)> = Vec::new();
	if let Some(dkim) = &config.dkim {
		let (selector, key_file, rsa) = match dkim.override_for(domain) {
			Some(entry) => (
				&entry.selector,
				&entry.key_file,
				entry.rsa_selector.as_ref().zip(entry.rsa_key_file.as_ref()),
			),
			None => (&dkim.selector, &dkim.key_file, None),
		};
		if let Ok(signer) = crate::dkim::Signer::load(selector, key_file) {
			dkim_owned.push((selector.clone(), signer.dns_record_value()));
		}
		if let Some((rsa_selector, rsa_key_file)) = rsa
			&& let Ok(value) = crate::dkim::rsa_record_value(rsa_key_file)
		{
			dkim_owned.push((rsa_selector.clone(), value));
		}
	}
	let tlsa = config
		.tls
		.as_ref()
		.and_then(|tls| std::fs::read_to_string(&tls.cert_file).ok())
		.and_then(|pem| dns_records::tlsa_full_cert(&pem));
	let recs = dns_records::build_records(
		&[domain.to_string()],
		&config.hostname,
		&dkim_owned,
		&dns_records::DomainDkim::new(),
		tlsa.as_deref(),
		&dns_records::mta_sts_id(config),
		dns_records::Services::all(),
		config.acme.as_ref().map(|a| a.directory_url.as_str()),
		config.public_ipv4,
		config.public_ipv6,
	);
	writeln!(out, "\nDNS records to publish for {domain}:")?;
	for entry in &recs {
		let r = &entry.record;
		let value = match r.kind {
			RecordKind::Txt => dns_records::txt_zone_form(&r.value),
			_ => r.value.clone(),
		};
		writeln!(out, "{} {} IN {} {}", r.name, r.ttl, r.kind.as_str(), value)?;
	}
	Ok(())
}

/// Validate and commit a config-edit domain mutation; the helper
/// unwraps the new domain so `add_domain` can return early on a bad
/// name, then the commit step prints the DNS records the operator must
/// publish.
pub fn commit_add(
	_config: &Config,
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	if dry_run {
		write!(out, "{}", document.dry_run()?)
			.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	let new_config = document.config()?;
	let outcome = document.commit()?;
	if outcome == crate::cli::config_edit::Outcome::Unchanged {
		writeln!(
			status,
			"domain {domain} already configured; nothing changed."
		)
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain {domain} added.")
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
	print_domain_records(&new_config, domain, out)
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
	crate::cli::config_edit::after_change_with(
		&new_config,
		outcome,
		true,
		status,
		crate::cli::stack::run,
	)
}

pub fn commit_remove(
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	if dry_run {
		write!(out, "{}", document.dry_run()?)
			.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	if outcome == crate::cli::config_edit::Outcome::Unchanged {
		writeln!(status, "domain {domain} already removed; nothing changed.")
			.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain {domain} removed.")
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
	let _ = config;
	crate::cli::config_edit::after_change_with(
		&config,
		outcome,
		true,
		status,
		crate::cli::stack::run,
	)
}

pub fn commit_alias(
	document: ConfigDocument,
	alias: &str,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	if dry_run {
		write!(out, "{}", document.dry_run()?)
			.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	if outcome == crate::cli::config_edit::Outcome::Unchanged {
		writeln!(
			status,
			"domain alias {alias} already {verb}; nothing changed."
		)
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain alias {alias} {verb}.")
		.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
	crate::cli::config_edit::after_change_with(
		&config,
		outcome,
		true,
		status,
		crate::cli::stack::run,
	)
}
