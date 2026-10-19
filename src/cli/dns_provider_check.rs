//! `dns provider check`: read-only, advisory capability inspection.

use std::io::Write;

use crate::config::Config;
use crate::dns::providers::check::{AccessReport, Outcome};

pub(super) fn run(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let mut names = vec![config.hostname.clone()];
	for domain in &config.domains {
		names.push(domain.clone());
		for service in ["autoconfig", "autodiscover", "mta-sts"] {
			names.push(format!("{service}.{domain}"));
		}
	}
	names.sort();
	names.dedup();
	let report = if let Some(dns) = &config.dns {
		if dns.provider.eq_ignore_ascii_case("manual") {
			AccessReport::unknown()
		} else if let Some(provider) = dns.build_for_host(&config.hostname) {
			let runtime = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.map_err(|_| "cannot start the async runtime")?;
			runtime.block_on(provider.check_access(&dns.zone, &names))
		} else {
			AccessReport::failed("provider credentials could not be resolved")
		}
	} else {
		AccessReport::unknown()
	};
	print(&report, json, out)
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
#[path = "dns_provider_check_tests.rs"]
mod tests;
