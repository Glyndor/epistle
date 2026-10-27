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
		// The SRV locators follow the configuration: a service the
		// operator turned off gets no locator.
		dns_records::Services::from_config(config),
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

/// One domain edit to commit: what the status line names, the verb it
/// prints, and the JSON `action` and fields.
pub(super) struct Commit<'a> {
	/// `domain example.org` or `domain alias example.net`.
	pub subject: String,
	/// The past tense in the status line (`added`).
	pub verb: &'a str,
	/// The word after `already` when nothing changed.
	pub already: &'a str,
	/// The JSON `action`.
	pub action: &'a str,
	/// The JSON fields naming the domain.
	pub fields: serde_json::Value,
	/// Print the records to publish for this domain after a change.
	pub records_for: Option<&'a str>,
}

/// Validate and commit a config-edit domain mutation, then restart mail.
/// `(dry_run, json)`: a dry run prints the diff; with `json` stdout gets
/// one object, holding the records to publish under `records`.
pub(super) fn commit(
	document: ConfigDocument,
	commit: Commit,
	(dry_run, json): (bool, bool),
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	let failure = |e: std::io::Error| crate::cli::resource::ResourceError::Failure(e.to_string());
	let Commit {
		subject,
		verb,
		already,
		action,
		mut fields,
		records_for,
	} = commit;
	if dry_run {
		let diff = document.dry_run()?;
		if json {
			let object = crate::cli::json_out::dry_run_object(action, fields, diff);
			return writeln!(out, "{object}")
				.map(|()| ExitCode::SUCCESS)
				.map_err(failure);
		}
		write!(out, "{diff}").map_err(failure)?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	let changed = outcome == crate::cli::config_edit::Outcome::Changed;
	if !changed {
		writeln!(status, "{subject} already {already}; nothing changed.").map_err(failure)?;
		if json {
			let reload = Some(crate::cli::json_out::Reload::None);
			let object = crate::cli::json_out::change_object(action, false, fields, reload);
			writeln!(out, "{object}").map_err(failure)?;
		}
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "{subject} {verb}.").map_err(failure)?;
	if let Some(domain) = records_for {
		if json {
			let mut printed = Vec::new();
			print_domain_records(&config, domain, &mut printed).map_err(failure)?;
			let text = String::from_utf8_lossy(&printed);
			let records: Vec<&str> = text
				.lines()
				.filter(|line| !line.is_empty() && !line.starts_with("DNS records to publish"))
				.collect();
			fields["records"] = records.into();
		} else {
			print_domain_records(&config, domain, out).map_err(failure)?;
		}
	}
	let (code, reload) = crate::cli::config_edit::after_change_reporting(
		&config,
		outcome,
		true,
		status,
		crate::cli::stack::run,
	)?;
	if json {
		let object = crate::cli::json_out::change_object(action, true, fields, Some(reload));
		writeln!(out, "{object}").map_err(failure)?;
	}
	Ok(code)
}

/// Commit `domain add`, printing the records to publish.
#[cfg(test)]
pub fn commit_add(
	_config: &Config,
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	commit(document, add_commit(domain), (dry_run, false), out, status)
}

/// Commit `domain remove`.
#[cfg(test)]
pub fn commit_remove(
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	commit(
		document,
		remove_commit(domain),
		(dry_run, false),
		out,
		status,
	)
}

/// Commit `domain alias add|remove`.
#[cfg(test)]
pub fn commit_alias(
	document: ConfigDocument,
	alias: &str,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	commit(
		document,
		alias_commit(alias, verb),
		(dry_run, false),
		out,
		status,
	)
}

/// The commit of `domain add`.
pub(super) fn add_commit(domain: &str) -> Commit<'_> {
	Commit {
		subject: format!("domain {domain}"),
		verb: "added",
		already: "configured",
		action: "add",
		fields: serde_json::json!({ "domain": domain }),
		records_for: Some(domain),
	}
}

/// The commit of `domain remove`.
pub(super) fn remove_commit(domain: &str) -> Commit<'_> {
	Commit {
		subject: format!("domain {domain}"),
		verb: "removed",
		already: "removed",
		action: "remove",
		fields: serde_json::json!({ "domain": domain }),
		records_for: None,
	}
}

/// The commit of `domain alias add|remove`; `verb` is `added` or `removed`.
pub(super) fn alias_commit<'a>(alias: &str, verb: &'a str) -> Commit<'a> {
	Commit {
		subject: format!("domain alias {alias}"),
		verb,
		already: verb,
		action: if verb == "added" {
			"alias add"
		} else {
			"alias remove"
		},
		fields: serde_json::json!({ "alias": alias }),
		records_for: None,
	}
}

#[cfg(test)]
#[path = "domain_writers_tests.rs"]
mod tests;
