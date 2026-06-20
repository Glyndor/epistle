//! `mail autoconfig`: emit the Mozilla/Thunderbird autoconfig XML
//! (`clientConfig` v1.1) for a domain, which the operator hosts at
//! `autoconfig.<domain>/mail/config-v1.1.xml` so Thunderbird configures itself
//! from an email address.

use std::process::ExitCode;

use crate::config::Config;

/// Write the Thunderbird autoconfig document for `domain` (defaults to the first
/// configured domain) to `out`.
pub(super) fn run(
	config: &Config,
	domain: Option<&str>,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let domain = match domain {
		Some(domain) => {
			if !config.domains.iter().any(|d| d == domain) {
				eprintln!("error: \"{domain}\" is not a configured domain");
				return ExitCode::FAILURE;
			}
			domain
		}
		None => match config.domains.first() {
			Some(domain) => domain.as_str(),
			None => {
				eprintln!("error: no domains are configured");
				return ExitCode::FAILURE;
			}
		},
	};

	let xml = crate::autodiscovery::autoconfig(domain, &config.hostname);
	if out.write_all(xml.as_bytes()).is_err() {
		eprintln!("error: writing autoconfig");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "autoconfig_tests.rs"]
mod tests;
