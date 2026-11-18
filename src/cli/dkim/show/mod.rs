//! `epistle dkim show`: the key in service, when it rotates next, and whether
//! the published DKIM TXT records match it.

use std::path::PathBuf;
#[cfg(test)]
use std::process::ExitCode;

use serde::Serialize;

use crate::config::Config;
use crate::dkim::Signer;
use crate::dkim::rotate::{self, ROTATE_INTERVAL_DAYS};
use crate::spf::DnsLookup;

mod keys;
mod render;
mod rotation_error;

pub(in crate::cli::dkim) use keys::signing_domains;
use keys::{compare, key_views, own_keys};
pub(in crate::cli::dkim) use render::render;

/// The previous selector still published during its overlap window.
#[derive(Debug, Serialize)]
pub(super) struct PreviousView {
	selector: String,
	retire_at: u64,
	/// The RSA selector retired with it, when the rotation replaced one.
	rsa_selector: Option<String>,
}

/// A per-domain override as `dkim show` reports it: the domain and the
/// ed25519 selector and key file it signs with (and the RSA ones): the
/// entry's until the domain's key rotates, the rotated ones after.
#[derive(Debug, Serialize)]
pub(super) struct DomainView {
	domain: String,
	selector: String,
	key_file: PathBuf,
	/// RSA dual-signing selector and key file, when configured.
	rsa_selector: Option<String>,
	rsa_key_file: Option<PathBuf>,
}

/// The key one hosted domain signs with, and who else signs with it. A
/// domain on the `[dkim]` default shares that key with every other domain
/// that has no `[[dkim.domain]]` entry.
#[derive(Debug, Serialize)]
pub(super) struct KeyView {
	domain: String,
	/// `dkim.domain` for a key of its own, `dkim` for the shared default.
	source: &'static str,
	selector: String,
	rsa_selector: Option<String>,
	/// The other domains that sign with this same key; empty for a key of
	/// the domain's own.
	shared_with: Vec<String>,
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
	/// Whether the selector came from the configured `[dkim]` block or
	/// from a per-domain override; empty when the lookup did not run.
	source: &'static str,
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
	/// Per-domain overrides as the configuration names them: every
	/// domain in this list signs with its own key, not the default.
	overrides: Vec<DomainView>,
	/// The key of every hosted domain, so a key several domains share is
	/// visible.
	keys: Vec<KeyView>,
	/// Records of the shared `[dkim]` key still published at a domain that
	/// has a key of its own: the split is not finished while any is listed.
	stale_records: Vec<String>,
	/// Records whose state could not be read, so the split cannot be called
	/// finished: a failure is never read as "gone".
	stale_unchecked: Vec<String>,
	records: Vec<RecordView>,
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
	let own = own_keys(config, dkim)?;
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
			// A per-domain override replaces the default for the domain
			// it names. The configured selectors are only checked for
			// domains without an override.
			if let Some(active) = own.get(&domain) {
				let mut override_expected: Vec<(String, Option<String>)> = Vec::new();
				match Signer::load(&active.ed.selector, &active.ed.key_file) {
					Ok(signer) => {
						override_expected
							.push((active.ed.selector.clone(), Some(signer.dns_record_value())));
					}
					Err(error) => {
						crate::cli::style::warn(format_args!(
							"cannot load DKIM key for {domain}: {error}"
						));
					}
				}
				if let Some(rsa) = &active.rsa {
					let value = crate::dkim::rsa_record_value(&rsa.key_file).ok();
					override_expected.push((rsa.selector.clone(), value));
				}
				for (selector, value) in &override_expected {
					let name = format!("{selector}._domainkey.{domain}");
					let status = compare(dns, &name, value.as_deref()).await;
					records.push(RecordView {
						domain: domain.clone(),
						selector: selector.clone(),
						name,
						status,
						source: "dkim.domain",
					});
				}
			} else {
				for (selector, value) in &expected {
					let name = format!("{selector}._domainkey.{domain}");
					let status = compare(dns, &name, value.as_deref()).await;
					records.push(RecordView {
						domain: domain.clone(),
						selector: selector.clone(),
						name,
						status,
						source: "dkim",
					});
				}
			}
		}
	}
	let keys = key_views(
		config,
		dkim,
		(
			&active.selector,
			rsa.as_ref().map(|rsa| rsa.selector.as_str()),
		),
		&own,
	);
	let (stale_records, stale_unchecked) = match dns {
		Some(dns) => match crate::dkim::stale::names(config) {
			Ok(candidates) => {
				let found = crate::dkim::stale::survey(dns, candidates).await;
				(
					found.shared.into_iter().map(|f| f.stale.name).collect(),
					found
						.unknown
						.into_iter()
						.map(|(r, why)| format!("{}: {why}", r.name))
						.collect(),
				)
			}
			Err(why) => (Vec::new(), vec![format!("cannot list the records: {why}")]),
		},
		None => (Vec::new(), Vec::new()),
	};
	let automatic = !config.dns.is_empty();
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
		last_request_error: rotation_error::current(
			rotate::last_error(&config.data_dir),
			rotated_at,
		),
		overrides: dkim
			.domain
			.iter()
			.filter_map(|entry| {
				let active = own.get(&entry.name.to_ascii_lowercase())?;
				Some(DomainView {
					domain: entry.name.clone(),
					selector: active.ed.selector.clone(),
					key_file: active.ed.key_file.clone(),
					rsa_selector: active.rsa.as_ref().map(|rsa| rsa.selector.clone()),
					rsa_key_file: active.rsa.as_ref().map(|rsa| rsa.key_file.clone()),
				})
			})
			.collect(),
		keys,
		stale_records,
		stale_unchecked,
		records,
	})
}

#[cfg(test)]
mod tests;
