//! `dns provider check`: read-only, advisory capability inspection.

use std::io::Write;

use crate::config::Config;
use crate::dns::providers::check::{AccessReport, Outcome};

pub(super) fn config_error(error: &crate::config::ConfigError) -> String {
	use crate::config::ConfigError;
	// Parser and validation messages may include expanded credential values.
	match error {
		ConfigError::Parse { source, .. } => match source.span() {
			Some(span) => format!("invalid TOML configuration near byte {}", span.start + 1),
			None => "invalid TOML configuration".into(),
		},
		ConfigError::Read { source, .. } => {
			format!("cannot read configuration: {}", source.kind())
		}
		ConfigError::InsecurePermissions { .. } => {
			"configuration permissions must be owner-only (0600 or 0400)".into()
		}
		ConfigError::MissingEnv(_) => {
			"configuration references an undefined environment variable".into()
		}
		ConfigError::Invalid(_) => "configuration validation failed".into(),
	}
}

pub(super) fn run(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	run_with(config, json, out, |dns, hostname| {
		dns.build_for_host(hostname)
	})
}

type Build<'a> = &'a mut dyn FnMut(
	&crate::config::Dns,
	&str,
)
	-> Option<std::sync::Arc<dyn crate::dns::provider::DnsProvider>>;

fn run_with(
	config: &Config,
	json: bool,
	out: &mut impl Write,
	mut build: impl FnMut(
		&crate::config::Dns,
		&str,
	) -> Option<std::sync::Arc<dyn crate::dns::provider::DnsProvider>>,
) -> Result<(), String> {
	let mut names = vec![config.hostname.clone()];
	for domain in &config.domains {
		names.push(domain.clone());
		for service in ["autoconfig", "autodiscover", "mta-sts"] {
			names.push(format!("{service}.{domain}"));
		}
	}
	names.sort();
	names.dedup();
	// A single `[dns]` reports as it always did. Several `[[dns]]` entries
	// each get their own report, labelled with the zone, so one credential
	// that fails is not hidden behind another that works.
	if config.dns.len() <= 1 {
		let report = match config.dns.first() {
			Some(dns) => entry_report(dns, &config.hostname, &names, &mut build)?,
			None => AccessReport::unknown(),
		};
		return print(&report, json, out);
	}
	let mut reports = Vec::new();
	for dns in &config.dns {
		let own: Vec<String> = names
			.iter()
			.filter(|name| {
				crate::dns::router::contains(
					&crate::dns::router::normalize(&dns.zone),
					&crate::dns::router::normalize(name),
				)
			})
			.cloned()
			.collect();
		reports.push((dns, entry_report(dns, &config.hostname, &own, &mut build)?));
	}
	print_all(&reports, json, out)
}

/// The access report of one entry: unknown for `manual`, a failure when its
/// credentials cannot be resolved, and the provider's own findings otherwise.
fn entry_report(
	dns: &crate::config::Dns,
	hostname: &str,
	names: &[String],
	build: Build<'_>,
) -> Result<AccessReport, String> {
	if dns.provider.eq_ignore_ascii_case("manual") {
		return Ok(AccessReport::unknown());
	}
	let Some(provider) = build(dns, hostname) else {
		return Ok(AccessReport::failed(
			"provider credentials could not be resolved",
		));
	};
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|_| "cannot start the async runtime")?;
	Ok(runtime.block_on(provider.check_access(&dns.zone, names)))
}

/// The reports of several entries: a JSON list with the zone and provider of
/// each, or the usual lines with the zone in front.
fn print_all(
	reports: &[(&crate::config::Dns, AccessReport)],
	json: bool,
	out: &mut impl Write,
) -> Result<(), String> {
	if json {
		let list: Vec<_> = reports
			.iter()
			.map(|(dns, report)| {
				serde_json::json!({
					"zone": dns.zone,
					"provider": dns.provider,
					"report": report,
				})
			})
			.collect();
		return super::resource::json(out, &list);
	}
	for (dns, report) in reports {
		let zone = crate::cli::term::sanitize(&dns.zone);
		let mut lines = Vec::new();
		print(report, false, &mut lines)?;
		for line in String::from_utf8_lossy(&lines).lines() {
			writeln!(out, "{zone}\t{line}").map_err(|error| error.to_string())?;
		}
	}
	Ok(())
}

pub(super) fn print(report: &AccessReport, json: bool, out: &mut impl Write) -> Result<(), String> {
	if json {
		return super::resource::json(out, report);
	}
	for (label, finding) in [
		("token_status", &report.token_status),
		("record_read", &report.record_read),
		("record_write", &report.record_write),
		("zones", &report.zones),
		("expiry", &report.expiry),
		("scope", &report.scope),
	] {
		let status = match finding.status {
			Outcome::Verified => "verified",
			Outcome::NotVerifiable => "not verifiable with this provider",
			Outcome::Failure => "failure",
		};
		writeln!(
			out,
			"{label}\t{status}\t{}",
			crate::cli::term::sanitize(&finding.detail)
		)
		.map_err(|error| error.to_string())?;
	}
	Ok(())
}

#[cfg(test)]
mod tests;
