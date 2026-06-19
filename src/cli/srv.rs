//! `mail srv-records`: print the RFC 6186 service-discovery SRV records (plus
//! the autoconfig/autodiscover CNAMEs) an operator publishes so clients can
//! configure themselves from just an email address. Manual-DNS mode: no
//! provider credentials needed.

use std::process::ExitCode;

use crate::config::Config;

/// One advertised service: SRV owner label, priority, and port.
struct Service {
	label: &'static str,
	priority: u16,
	port: u16,
}

/// Services epistle offers, in RFC 6186 form. Secure (implicit-TLS) variants
/// are preferred (lower priority) over STARTTLS. Plaintext POP3 is never
/// offered, so it is advertised as unavailable (target ".").
const SERVICES: &[Service] = &[
	Service {
		label: "_submissions._tcp",
		priority: 10,
		port: 465,
	},
	Service {
		label: "_submission._tcp",
		priority: 20,
		port: 587,
	},
	Service {
		label: "_imaps._tcp",
		priority: 10,
		port: 993,
	},
	Service {
		label: "_imap._tcp",
		priority: 20,
		port: 143,
	},
	Service {
		label: "_pop3s._tcp",
		priority: 10,
		port: 995,
	},
];

/// Write the SRV (and a `_pop3._tcp` "unavailable") records for every configured
/// domain, pointing at the server hostname.
pub(super) fn run(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	if config.domains.is_empty() {
		eprintln!("error: no domains are configured");
		return ExitCode::FAILURE;
	}
	let host = &config.hostname;
	for domain in &config.domains {
		for service in SERVICES {
			let _ = writeln!(
				out,
				"{}.{domain}. 3600 IN SRV {} 1 {} {host}.",
				service.label, service.priority, service.port
			);
		}
		// RFC 6186 §6: signal that plaintext POP3 is not available.
		let _ = writeln!(out, "_pop3._tcp.{domain}. 3600 IN SRV 0 0 0 .");
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "srv_tests.rs"]
mod tests;
