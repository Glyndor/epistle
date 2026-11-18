//! `epistle domain`: low-level helpers that emit DNS records and the
//! shared commit/restart policy. Lives in a sibling so `domain/mod.rs`
//! stays under the per-file code-line budget.

use std::io::Write;

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
	// The records come from the same function `dns-records`, `verify-dns`
	// and the publisher read, restricted to this domain: its role and the
	// `skip` groups leave out the same records everywhere.
	let desired = match crate::dns::desired::for_domains(config, &[domain.to_string()]) {
		Ok(desired) => desired,
		Err(errors) => {
			return writeln!(
				out,
				"\nThe DNS records are not listed: {}.",
				errors.join("; ")
			);
		}
	};
	for warning in &desired.warnings {
		writeln!(out, "\nNot listed: {warning}.")?;
	}
	writeln!(out, "\nDNS records to publish for {domain}:")?;
	for entry in &desired.records {
		let r = &entry.record;
		let value = match r.kind {
			RecordKind::Txt => dns_records::txt_zone_form(&r.value),
			_ => r.value.clone(),
		};
		writeln!(out, "{} {} IN {} {}", r.name, r.ttl, r.kind.as_str(), value)?;
	}
	for group in &desired.skipped {
		writeln!(
			out,
			"skipped by configuration ({}): {} records are not published",
			group.group.name(),
			group.records.len()
		)?;
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

/// The DNS records of `domain` as the lines `--json` reports under
/// `records`.
pub(super) fn record_lines(config: &Config, domain: &str) -> std::io::Result<Vec<String>> {
	let mut printed = Vec::new();
	print_domain_records(config, domain, &mut printed)?;
	let text = String::from_utf8_lossy(&printed);
	Ok(text
		.lines()
		.filter(|line| {
			!line.is_empty()
				&& !line.starts_with("DNS records to publish")
				&& !line.starts_with("skipped by configuration")
		})
		.map(str::to_string)
		.collect())
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

mod state;
pub(super) use state::{Mode, commit_state};

#[cfg(test)]
mod tests;
