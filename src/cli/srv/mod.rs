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
/// With `json` the records are one JSON array of `{"name", "ttl", "type",
/// "value"}` objects, the same shape `dns-records --json` prints.
pub(super) fn run(config: &Config, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	if config.domains.is_empty() {
		super::style::error("no domains are configured");
		return ExitCode::FAILURE;
	}
	let host = &config.hostname;
	let mut rows: Vec<(String, String)> = Vec::new();
	for domain in &config.domains {
		for service in SERVICES {
			rows.push((
				format!("{}.{domain}.", service.label),
				format!("{} 1 {} {host}.", service.priority, service.port),
			));
		}
		// RFC 6186 §6: signal that plaintext POP3 is not available.
		rows.push((format!("_pop3._tcp.{domain}."), "0 0 0 .".to_string()));
	}
	if json {
		let rows: Vec<serde_json::Value> = rows
			.iter()
			.map(
				|(name, value)| serde_json::json!({ "name": name, "ttl": 3600, "type": "SRV", "value": value }),
			)
			.collect();
		return super::json_out::print(out, &serde_json::Value::from(rows));
	}
	for (name, value) in rows {
		let _ = writeln!(out, "{name} 3600 IN SRV {value}");
	}
	ExitCode::SUCCESS
}

#[cfg(test)]
mod tests;
