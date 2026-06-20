//! `mail autodiscover`: emit the Microsoft Autodiscover v1 (POX) XML response
//! for a domain, which the operator hosts at
//! `autodiscover.<domain>/autodiscover/autodiscover.xml` so Outlook configures
//! itself from an email address.
//!
//! Autodiscover v1 is the plain-old-XML (POX) response Outlook desktop consumes
//! for IMAP/SMTP accounts. The document is per-domain; `LoginName` is omitted so
//! the client uses the address the user entered. Autodiscover v2 (a live JSON
//! lookup endpoint) is a separate, dynamic concern and is not emitted here.

use std::process::ExitCode;

use crate::config::Config;

/// Write the Autodiscover document for `domain` (defaults to the first
/// configured domain) to `out`.
pub(super) fn run(
	config: &Config,
	domain: Option<&str>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// The POX response is keyed on the server hostname, not the domain, but we
	// still validate the requested domain so the operator gets a clear error
	// rather than a document for a domain this server does not host.
	match domain {
		Some(domain) => {
			if !config.domains.iter().any(|d| d == domain) {
				eprintln!("error: \"{domain}\" is not a configured domain");
				return ExitCode::FAILURE;
			}
		}
		None => {
			if config.domains.is_empty() {
				eprintln!("error: no domains are configured");
				return ExitCode::FAILURE;
			}
		}
	}

	let xml = crate::autodiscovery::autodiscover(&config.hostname);
	if out.write_all(xml.as_bytes()).is_err() {
		eprintln!("error: writing autodiscover");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "autodiscover_tests.rs"]
mod tests;
