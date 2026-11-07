//! `epistle dkim cleanup`: list the DKIM key files and TXT records that no
//! rotation uses, and ask the running server to remove them.
//!
//! Like `dkim rotate`, nothing is removed here: the server is the only
//! writer of keys and records, and it removes only what is still unused
//! when it serves the request, so a rotation that starts in between keeps
//! everything it names.
//!
//! The report is the server's: the server that serves the request is the
//! one that removes the leftovers, so the zone is read the way that server
//! can read it. With the certificates container on, that server holds no
//! DNS credential: it cannot read the zone, the TXT records are not
//! checked, and the command says so and fails instead of promising a
//! removal that will not happen. The leftover key files are removed all
//! the same: they are found from the rotation state alone.

use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::serve::tasks::{DkimRotationPlan, DnsWrite, decide_dkim_rotation};
use crate::cli::{prompt, style};
use crate::config::Config;
use crate::dkim::rotate::{find_orphans, request_cleanup};
use crate::dns::handoff::{HandoffProvider, Writer};
use crate::dns::provider::DnsProvider;

/// Run `dkim cleanup` with the provider the server that removes the
/// leftovers holds.
pub(super) fn cleanup(
	config: &Config,
	dry_run: bool,
	yes: bool,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let write = DnsWrite::for_install(config);
	let provider = provider_of(config, &write);
	cleanup_with(config, &write, provider.as_deref(), dry_run, yes, json, out)
}

/// The provider the server that removes the leftovers reads the zone with:
/// the one this installation holds, or the hand-off the certificates
/// container serves, which cannot read the zone.
fn provider_of(config: &Config, write: &DnsWrite) -> Option<Arc<dyn DnsProvider>> {
	match write {
		DnsWrite::Direct => config.dns.build_for_host(&config.hostname),
		DnsWrite::Handoff(dir) => Some(Arc::new(HandoffProvider::new(Writer::at(dir.clone())))),
	}
}

/// [`cleanup`] against any provider; `None` when there is none to list.
pub(super) fn cleanup_with(
	config: &Config,
	write: &DnsWrite,
	provider: Option<&dyn DnsProvider>,
	dry_run: bool,
	yes: bool,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let Some(dkim) = &config.dkim else {
		style::error("[dkim] is not configured");
		return ExitCode::FAILURE;
	};
	let plan = decide_dkim_rotation(config, write);
	let (domains, served) = match &plan {
		DkimRotationPlan::Run {
			signing_domains,
			out_of_zone,
			..
		} => (
			signing_domains.clone(),
			out_of_zone.is_empty() && provider.is_some(),
		),
		DkimRotationPlan::Off => (Vec::new(), false),
	};
	let zones = config.dns.zones();
	let keep = dkim.kept_selectors();
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let orphans = match runtime.block_on(find_orphans(
		&config.data_dir,
		provider,
		&zones,
		&domains,
		&keep,
	)) {
		Ok(orphans) => orphans,
		Err(error) => {
			style::error(format_args!("dkim cleanup refused: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut report = crate::cli::json_out::Report::new(out, json);
	// The TXT records are removed by the server that serves the request,
	// and only if it can read the zone. When it cannot, they were neither
	// found nor removed: the command says so and fails, instead of
	// promising a removal that cannot happen.
	let unchecked = orphans.unlisted.clone();
	if let Some(reason) = &unchecked {
		report.line(format_args!("TXT records not checked: {reason}"));
	}
	for path in &orphans.key_files {
		report.line(format_args!("remove key file {}", path.display()));
	}
	for name in &orphans.records {
		report.line(format_args!("delete TXT {name}"));
	}
	let files: Vec<String> = orphans
		.key_files
		.iter()
		.map(|path| path.display().to_string())
		.collect();
	let mut result = serde_json::json!({
		"result": "queued", "action": "cleanup", "key_files": files,
		"records": orphans.records, "records_unchecked": orphans.unlisted,
	});
	if unchecked.is_some() {
		result["result"] = "failed".into();
	}
	if orphans.is_empty() {
		if unchecked.is_none() {
			report.line("nothing to clean up");
			result["result"] = "unchanged".into();
			return report.object(result);
		}
		// The zone was not read, so what it holds is unknown: the
		// leftovers in it may be there, and nothing was queued.
		return report.object_with(result, ExitCode::FAILURE);
	}
	if dry_run {
		report.line("dry run: nothing changed");
		result["result"] = "dry-run".into();
		return report.object_with(result, exit_for(unchecked.is_some()));
	}
	if !served {
		style::error(
			"the server removes these only while it rotates DKIM keys, which this configuration does not do; remove the key files by hand",
		);
		result["result"] = "failed".into();
		return report.object_with(result, ExitCode::FAILURE);
	}
	let question = match &unchecked {
		Some(reason) => format!(
			"Ask the server to remove {} key file(s) and {} TXT record(s)? It cannot read every zone: {reason}",
			orphans.key_files.len(),
			orphans.records.len()
		),
		None => format!(
			"Ask the server to remove {} key file(s) and {} TXT record(s)?",
			orphans.key_files.len(),
			orphans.records.len()
		),
	};
	if let Err(code) = prompt::confirm_destructive("dkim cleanup", &question, yes) {
		return code;
	}
	if let Err(error) = request_cleanup(&config.data_dir) {
		style::error(format_args!("cannot write the cleanup request: {error}"));
		return ExitCode::FAILURE;
	}
	if unchecked.is_some() {
		report.line(
			"queued: the running server removes the leftover key files within a minute (at its next start if it is stopped); the TXT records it could not check stay published",
		);
	} else {
		report.line(
			"queued: the running server removes what is still unused within a minute (at its next start if it is stopped)",
		);
	}
	report.object_with(result, exit_for(unchecked.is_some()))
}

/// The exit code of a cleanup: a failure when the TXT records were not
/// checked, because the command did not do the whole job and the operator
/// has to hear it.
fn exit_for(unchecked: bool) -> ExitCode {
	if unchecked {
		ExitCode::FAILURE
	} else {
		ExitCode::SUCCESS
	}
}

#[cfg(test)]
mod tests;
