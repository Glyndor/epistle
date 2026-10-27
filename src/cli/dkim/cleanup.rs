//! `epistle dkim cleanup`: list the DKIM key files and TXT records that no
//! rotation uses, and ask the running server to remove them.
//!
//! Like `dkim rotate`, nothing is removed here: the server is the only
//! writer of keys and records, and it removes only what is still unused
//! when it serves the request, so a rotation that starts in between keeps
//! everything it names.

use std::process::ExitCode;

use crate::cli::serve_tasks::{DkimRotationPlan, decide_dkim_rotation};
use crate::cli::{prompt, style};
use crate::config::Config;
use crate::dkim::rotate::{find_orphans, request_cleanup};
use crate::dns::provider::DnsProvider;

/// Run `dkim cleanup` with the provider the configuration builds.
pub(super) fn cleanup(
	config: &Config,
	dry_run: bool,
	yes: bool,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let provider = config
		.dns
		.as_ref()
		.and_then(|dns| dns.build_for_host(&config.hostname));
	cleanup_with(config, provider.as_deref(), dry_run, yes, json, out)
}

/// [`cleanup`] against any provider; `None` when there is none to list.
pub(super) fn cleanup_with(
	config: &Config,
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
		zone,
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
	if let Some(reason) = &orphans.unlisted {
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
	if orphans.is_empty() {
		report.line("nothing to clean up");
		result["result"] = "unchanged".into();
		return report.object(result);
	}
	if dry_run {
		report.line("dry run: nothing changed");
		result["result"] = "dry-run".into();
		return report.object(result);
	}
	if !served {
		style::error(
			"the server removes these only while it rotates DKIM keys, which this configuration does not do; remove the key files by hand",
		);
		return ExitCode::FAILURE;
	}
	let question = format!(
		"Ask the server to remove {} key file(s) and {} TXT record(s)?",
		orphans.key_files.len(),
		orphans.records.len()
	);
	if let Err(code) = prompt::confirm_destructive("dkim cleanup", &question, yes) {
		return code;
	}
	if let Err(error) = request_cleanup(&config.data_dir) {
		style::error(format_args!("cannot write the cleanup request: {error}"));
		return ExitCode::FAILURE;
	}
	report.line(
		"queued: the running server removes what is still unused within a minute (at its next start if it is stopped)",
	);
	report.object(result)
}

#[cfg(test)]
#[path = "cleanup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cleanup_tests_per_domain.rs"]
mod tests_per_domain;
