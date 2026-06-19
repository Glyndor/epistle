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

	let xml = build_autoconfig(domain, &config.hostname);
	if out.write_all(xml.as_bytes()).is_err() {
		eprintln!("error: writing autoconfig");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

/// Build the `clientConfig` document: IMAP over implicit TLS (993) and SMTP
/// submission over STARTTLS (587), authenticated with the full email address.
fn build_autoconfig(domain: &str, hostname: &str) -> String {
	let domain = escape(domain);
	let host = escape(hostname);
	format!(
		r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
	<emailProvider id="{domain}">
		<domain>{domain}</domain>
		<displayName>{domain} mail</displayName>
		<displayShortName>{domain}</displayShortName>
		<incomingServer type="imap">
			<hostname>{host}</hostname>
			<port>993</port>
			<socketType>SSL</socketType>
			<authentication>password-cleartext</authentication>
			<username>%EMAILADDRESS%</username>
		</incomingServer>
		<outgoingServer type="smtp">
			<hostname>{host}</hostname>
			<port>587</port>
			<socketType>STARTTLS</socketType>
			<authentication>password-cleartext</authentication>
			<username>%EMAILADDRESS%</username>
		</outgoingServer>
	</emailProvider>
</clientConfig>
"#
	)
}

/// Escape the five XML special characters for safe interpolation.
fn escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

#[cfg(test)]
#[path = "autoconfig_tests.rs"]
mod tests;
