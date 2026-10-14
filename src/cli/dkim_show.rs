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
	/// The RSA selector retired with it, when the rotation replaced one.
	rsa_selector: Option<String>,
}

/// A rotation the server began and has not committed or withdrawn yet.
#[derive(Debug, Serialize)]
pub(super) struct InProgressView {
	selector: String,
	started_at: u64,
	/// Why the rotation is being taken back, once it is.
	withdrawing: Option<String>,
	/// The RSA selector rotated in the same step, when the server dual-signs.
	rsa_selector: Option<String>,
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
	/// The RSA dual-signing key in service; `None` without dual signing.
	rsa_selector: Option<String>,
	rsa_key_file: Option<PathBuf>,
	/// `state` when a rotation put the RSA key in service, `config` before.
	rsa_source: Option<&'static str>,
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
	let rsa = rotate::active_rsa(dkim, &config.data_dir).map_err(|e| e.to_string())?;
	let mut expected: Vec<(String, Option<String>)> =
		vec![(active.selector.clone(), Some(signer.dns_record_value()))];
	// An RSA key that does not load is still looked up, by presence only.
	if let Some(rsa) = &rsa {
		let value = crate::dkim::rsa_record_value(&rsa.key_file).ok();
		expected.push((rsa.selector.clone(), value));
	}
	let previous = state.as_ref().and_then(|s| s.previous.as_ref());
	if let Some(previous) = previous {
		let value = Signer::load(&previous.selector, &previous.key_file)
			.ok()
			.map(|s| s.dns_record_value());
		expected.push((previous.selector.clone(), value));
		if let Some(old) = &previous.rsa {
			let value = crate::dkim::rsa_record_value(&config.data_dir.join(&old.key_file)).ok();
			expected.push((old.selector.clone(), value));
		}
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
			rsa_selector: p.rsa.as_ref().map(|rsa| rsa.selector.clone()),
		}),
		in_progress: state
			.as_ref()
			.and_then(|s| s.pending.as_ref())
			.map(|p| InProgressView {
				selector: p.selector.clone(),
				started_at: p.started_at,
				withdrawing: p.withdrawing.clone(),
				rsa_selector: p.rsa.as_ref().map(|rsa| rsa.selector.clone()),
			}),
		rsa_source: rsa.as_ref().map(|_| {
			if state.as_ref().is_some_and(|s| s.rsa.is_some()) {
				"state"
			} else {
				"config"
			}
		}),
		rsa_key_file: rsa.as_ref().map(|rsa| rsa.key_file.clone()),
		rsa_selector: rsa.map(|rsa| rsa.selector),
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

/// `ed` alone, or `ed and rsa` when an RSA selector goes with it.
fn pair(ed: &str, rsa: Option<&str>) -> String {
	match rsa {
		Some(rsa) => format!("{ed} and {rsa}"),
		None => ed.to_string(),
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
	if let Some(rsa) = &view.rsa_selector {
		writeln!(
			out,
			"rsa selector: {rsa} (from {})",
			view.rsa_source.unwrap_or("config")
		)?;
	}
	if let Some(previous) = &view.previous {
		writeln!(
			out,
			"previous: {} (retires at {})",
			pair(&previous.selector, previous.rsa_selector.as_deref()),
			previous.retire_at
		)?;
	}
	if let Some(next) = &view.in_progress {
		let to = pair(&next.selector, next.rsa_selector.as_deref());
		match &next.withdrawing {
			Some(reason) => writeln!(out, "rotation to {to} is being withdrawn: {reason}")?,
			None if next.rsa_selector.is_some() => writeln!(
				out,
				"rotation to {to} in progress since {}; {} sign until DNS shows the new keys",
				next.started_at,
				pair(&view.selector, view.rsa_selector.as_deref())
			)?,
			None => writeln!(
				out,
				"rotation to {to} in progress since {}; {} signs until DNS shows the new key",
				next.started_at, view.selector
			)?,
		}
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

#[cfg(test)]
#[path = "dkim_show_tests_rsa.rs"]
mod tests_rsa;
