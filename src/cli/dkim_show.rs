//! `epistle dkim show`: the key in service, when it rotates next, and whether
//! the published DKIM TXT records match it.

use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

use crate::config::Config;
use crate::dkim::Signer;
use crate::dkim::rotate::{self, ROTATE_INTERVAL_DAYS};
use crate::spf::DnsLookup;

/// The previous selector still published during its overlap window.
#[derive(Debug, Serialize)]
pub(super) struct PreviousView {
	selector: String,
	retire_at: u64,
}

/// A rotation the server began and has not committed or withdrawn yet.
#[derive(Debug, Serialize)]
pub(super) struct InProgressView {
	selector: String,
	started_at: u64,
	/// Why the rotation is being taken back, once it is.
	withdrawing: Option<String>,
}

/// One published record compared with what the key in service implies.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct RecordView {
	domain: String,
	selector: String,
	name: String,
	/// `ok`, `differs`, `missing` or `lookup-error`.
	status: &'static str,
}

/// Everything `dkim show` prints.
#[derive(Debug, Serialize)]
pub(super) struct DkimView {
	selector: String,
	key_file: PathBuf,
	algorithm: &'static str,
	/// `state` when the rotation state names the key, `config` before the
	/// first rotation.
	source: &'static str,
	rotated_at: Option<u64>,
	/// Epoch second of the next scheduled rotation; `None` when the server
	/// would rotate at its next tick or cannot rotate (no `[dns]`).
	next_rotation_due: Option<u64>,
	automatic_rotation: bool,
	previous: Option<PreviousView>,
	/// A rotation in progress; the selector above signs until it commits.
	in_progress: Option<InProgressView>,
	rsa_selector: Option<String>,
	rotation_requested_at: Option<u64>,
	last_request_error: Option<String>,
	records: Vec<RecordView>,
}

/// Every domain the relay signs for, lowercase and sorted.
pub(super) fn signing_domains(config: &Config) -> Vec<String> {
	let mut all = std::collections::BTreeSet::new();
	all.extend(config.domains.iter().map(|d| d.to_ascii_lowercase()));
	all.extend(config.domain_aliases.keys().map(|d| d.to_ascii_lowercase()));
	all.into_iter().collect()
}

/// The `p=` tag of a DKIM record with whitespace removed.
fn public_key(record: &str) -> Option<String> {
	record
		.split(';')
		.find_map(|tag| tag.trim().strip_prefix("p="))
		.map(|value| value.split_whitespace().collect())
}

/// Compare the TXT records at `name` with `expected` (a full record value;
/// `None` means only presence of a DKIM record is checked).
async fn compare(dns: &dyn DnsLookup, name: &str, expected: Option<&str>) -> &'static str {
	let Ok(records) = dns.txt(name).await else {
		return "lookup-error";
	};
	let dkim: Vec<&String> = records
		.iter()
		.filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dkim1"))
		.collect();
	if dkim.is_empty() {
		return "missing";
	}
	match expected.and_then(public_key) {
		Some(want) if !dkim.iter().any(|r| public_key(r).as_deref() == Some(&want)) => "differs",
		_ => "ok",
	}
}

/// Build the view. `dns` is `None` when the caller does not want lookups.
pub(super) async fn build(
	config: &Config,
	dns: Option<&dyn DnsLookup>,
) -> Result<DkimView, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	let active = rotate::active_ed25519(dkim, &config.data_dir).map_err(|e| e.to_string())?;
	let state = rotate::read_state(&config.data_dir).map_err(|e| e.to_string())?;
	let signer = Signer::load(&active.selector, &active.key_file).map_err(|e| e.to_string())?;
	let mut expected: Vec<(String, Option<String>)> =
		vec![(active.selector.clone(), Some(signer.dns_record_value()))];
	if let (Some(selector), Some(key_file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
		let value = signer
			.with_rsa(selector, key_file)
			.map_err(|e| e.to_string())?
			.rsa_dns_record_value();
		expected.push((selector.clone(), value));
	}
	let previous = state.as_ref().and_then(|s| s.previous.as_ref());
	if let Some(previous) = previous {
		let value = Signer::load(&previous.selector, &previous.key_file)
			.ok()
			.map(|s| s.dns_record_value());
		expected.push((previous.selector.clone(), value));
	}
	let mut records = Vec::new();
	if let Some(dns) = dns {
		for domain in signing_domains(config) {
			for (selector, value) in &expected {
				let name = format!("{selector}._domainkey.{domain}");
				let status = compare(dns, &name, value.as_deref()).await;
				records.push(RecordView {
					domain: domain.clone(),
					selector: selector.clone(),
					name,
					status,
				});
			}
		}
	}
	let automatic = config.dns.is_some();
	let rotated_at = state.as_ref().map(|s| s.rotated_at);
	Ok(DkimView {
		selector: active.selector,
		key_file: active.key_file,
		algorithm: "ed25519",
		source: if state.is_some() { "state" } else { "config" },
		rotated_at,
		next_rotation_due: rotated_at
			.filter(|_| automatic)
			.map(|at| at + ROTATE_INTERVAL_DAYS * 86_400),
		automatic_rotation: automatic,
		previous: previous.map(|p| PreviousView {
			selector: p.selector.clone(),
			retire_at: p.retire_at,
		}),
		in_progress: state
			.as_ref()
			.and_then(|s| s.pending.as_ref())
			.map(|p| InProgressView {
				selector: p.selector.clone(),
				started_at: p.started_at,
				withdrawing: p.withdrawing.clone(),
			}),
		rsa_selector: dkim.rsa_selector.clone(),
		rotation_requested_at: rotate::pending_request(&config.data_dir).map(|r| r.requested_at),
		last_request_error: rotate::last_error(&config.data_dir),
		records,
	})
}

/// Print the view as text or JSON.
pub(super) fn render(view: &DkimView, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	let result = if json {
		serde_json::to_writer_pretty(&mut *out, view)
			.map_err(std::io::Error::other)
			.and_then(|()| writeln!(out))
	} else {
		render_text(view, out)
	};
	if result.is_ok() {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

fn when(epoch: Option<u64>) -> String {
	epoch.map_or_else(|| "-".to_string(), |e| e.to_string())
}

fn render_text(view: &DkimView, out: &mut impl std::io::Write) -> std::io::Result<()> {
	writeln!(out, "selector: {} ({})", view.selector, view.algorithm)?;
	writeln!(
		out,
		"key file: {} (from {})",
		view.key_file.display(),
		view.source
	)?;
	writeln!(out, "rotated at: {}", when(view.rotated_at))?;
	if !view.automatic_rotation {
		writeln!(out, "next rotation: never ([dns] is not configured)")?;
	} else if view.next_rotation_due.is_none() {
		writeln!(out, "next rotation: at the server's next hourly tick")?;
	} else {
		writeln!(out, "next rotation: {}", when(view.next_rotation_due))?;
	}
	if let Some(previous) = &view.previous {
		writeln!(
			out,
			"previous: {} (retires at {})",
			previous.selector, previous.retire_at
		)?;
	}
	if let Some(next) = &view.in_progress {
		match &next.withdrawing {
			Some(reason) => writeln!(
				out,
				"rotation to {} is being withdrawn: {reason}",
				next.selector
			)?,
			None => writeln!(
				out,
				"rotation to {} in progress since {}; {} signs until DNS shows the new key",
				next.selector, next.started_at, view.selector
			)?,
		}
	}
	if let Some(rsa) = &view.rsa_selector {
		writeln!(out, "rsa selector: {rsa}")?;
	}
	if let Some(at) = view.rotation_requested_at {
		writeln!(out, "rotation requested at {at}, waiting for the server")?;
	}
	if let Some(error) = &view.last_request_error {
		writeln!(out, "last rotation error: {error}")?;
	}
	for record in &view.records {
		writeln!(out, "{} {}", record.status, record.name)?;
	}
	Ok(())
}

#[cfg(test)]
#[path = "dkim_show_tests.rs"]
mod tests;
