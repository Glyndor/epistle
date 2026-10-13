//! `epistle dkim cleanup`: list the DKIM key files and TXT records that no
//! rotation uses, and ask the running server to remove them.
//!
//! Like `dkim rotate`, nothing is removed here: the server is the only
//! writer of keys and records, and it removes only what is still unused
//! when it serves the request, so a rotation that starts in between keeps
//! everything it names.

use std::process::ExitCode;

use super::serve_tasks::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;
use crate::dkim::rotate::{find_orphans, request_cleanup};
use crate::dns::provider::DnsProvider;

/// Run `dkim cleanup` with the provider the configuration builds.
pub(super) fn cleanup(
	config: &Config,
	dry_run: bool,
	yes: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let provider = config
		.dns
		.as_ref()
		.and_then(|dns| dns.build_for_host(&config.hostname));
	cleanup_with(config, provider.as_deref(), dry_run, yes, out)
}

/// [`cleanup`] against any provider; `None` when there is none to list.
pub(super) fn cleanup_with(
	config: &Config,
	provider: Option<&dyn DnsProvider>,
	dry_run: bool,
	yes: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let Some(dkim) = &config.dkim else {
		super::style::error("[dkim] is not configured");
		return ExitCode::FAILURE;
	};
	let plan = decide_dkim_rotation(config);
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
	let zone = config.dns.as_ref().map_or("", |dns| dns.zone.as_str());
	let keep: Vec<String> = std::iter::once(dkim.selector.clone())
		.chain(dkim.rsa_selector.clone())
		.collect();
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			super::style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let orphans = match runtime.block_on(find_orphans(
		&config.data_dir,
		provider,
		zone,
		&domains,
		&keep,
	)) {
		Ok(orphans) => orphans,
		Err(error) => {
			super::style::error(format_args!("dkim cleanup refused: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if let Some(reason) = &orphans.unlisted {
		let _ = writeln!(out, "TXT records not checked: {reason}");
	}
	for path in &orphans.key_files {
		let _ = writeln!(out, "remove key file {}", path.display());
	}
	for name in &orphans.records {
		let _ = writeln!(out, "delete TXT {name}");
	}
	if orphans.is_empty() {
		let _ = writeln!(out, "nothing to clean up");
		return ExitCode::SUCCESS;
	}
	if dry_run {
		let _ = writeln!(out, "dry run: nothing changed");
		return ExitCode::SUCCESS;
	}
	if !served {
		super::style::error(
			"the server removes these only while it rotates DKIM keys, which this configuration does not do; remove the key files by hand",
		);
		return ExitCode::FAILURE;
	}
	let question = format!(
		"Ask the server to remove {} key file(s) and {} TXT record(s)?",
		orphans.key_files.len(),
		orphans.records.len()
	);
	if let Err(code) = super::prompt::confirm_destructive("dkim cleanup", &question, yes) {
		return code;
	}
	if let Err(error) = request_cleanup(&config.data_dir) {
		super::style::error(format_args!("cannot write the cleanup request: {error}"));
		return ExitCode::FAILURE;
	}
	let _ = writeln!(
		out,
		"queued: the running server removes what is still unused within a minute (at its next start if it is stopped)"
	);
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "dkim_cleanup_tests.rs"]
mod tests;
