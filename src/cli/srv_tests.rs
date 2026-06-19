//! Tests for the RFC 6186 SRV-record emitter.

use super::*;

fn config(domains: &[&str]) -> Config {
	let list = domains
		.iter()
		.map(|d| format!("\"{d}\""))
		.collect::<Vec<_>>()
		.join(", ");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [{list}]\n"
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn emits_srv_records_per_domain() {
	let config = config(&["example.org", "example.net"]);
	let mut out = Vec::new();
	assert_eq!(run(&config, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	// Secure services for each domain, pointing at the server hostname.
	assert!(text.contains("_imaps._tcp.example.org. 3600 IN SRV 10 1 993 mail.example.org."));
	assert!(text.contains("_submission._tcp.example.net. 3600 IN SRV 20 1 587 mail.example.org."));
	assert!(text.contains("_submissions._tcp.example.org. 3600 IN SRV 10 1 465 mail.example.org."));
	// Plaintext POP3 advertised as unavailable.
	assert!(text.contains("_pop3._tcp.example.org. 3600 IN SRV 0 0 0 ."));
	// One block per domain: 6 lines each.
	assert_eq!(text.lines().count(), 12);
}

#[test]
fn no_domains_is_an_error() {
	let config = config(&[]);
	let mut out = Vec::new();
	assert_eq!(run(&config, &mut out), ExitCode::FAILURE);
	assert!(out.is_empty());
}
