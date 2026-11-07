//! ACME auto-enable for public hostnames.
//!
//! The `init` answers file gets three knobs: a per-answers `acme`
//! section with `enabled` and `contact`. When `enabled` is unset and
//! the hostname is public (a real DNS name, not `localhost` / `127.0.0.1`
//! / `.local` / `.internal` / `.test` / `.example`), init enables ACME
//! automatically: it writes an `[acme]` block pointing at Let's
//! Encrypt production, the `acme` listener on port 80, and the
//! compose file that publishes it. These tests pin the decision and
//! the shape of the config it produces; the run that writes the files
//! lives in the sibling `acme_apply.rs`.
//!
//! Sister to `src/cli/init/apply/tests/listeners/implicit_tls.rs` because both files cover
//! the ports `init` publishes.

use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use super::*;
use crate::cli::init::answers::{Mode, Services};

pub(super) fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

pub(super) fn cert_key_ed() -> (PathBuf, PathBuf, PathBuf) {
	(
		PathBuf::from("/var/lib/epistle/keys/cert.pem"),
		PathBuf::from("/var/lib/epistle/keys/key.pem"),
		PathBuf::from("/var/lib/epistle/keys/s1.pem"),
	)
}

/// Public hostname with no `acme` answers section -> init enables
/// ACME. The `[acme]` block carries the Let's Encrypt production
/// directory, the postmaster contact at the first configured
/// domain, and the hostname as the only domain. The `acme`
/// listener on port 80 is part of the listeners array so the HTTP-
/// 01 challenge responder is reachable from the public internet.
/// The `[tls]` section points at the ACME cert / key paths so the
/// server can boot using the self-signed bootstrap cert init writes
/// there; the renewal loop overwrites those files in place once
/// Let's Encrypt issues.
#[test]
fn build_config_enables_acme_by_default_for_public_hostname() {
	let answers = answers_minimal();
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with public hostname");
	let acme = desired
		.acme
		.as_ref()
		.expect("acme block must be written for a public hostname");
	assert!(
		acme.directory_url
			.starts_with("https://acme-v02.api.letsencrypt.org/directory"),
		"acme.directory_url must be Let's Encrypt production; got {:?}",
		acme.directory_url
	);
	assert_eq!(
		acme.contacts,
		vec!["mailto:postmaster@example.org".to_string()],
		"acme.contacts must default to postmaster at the first configured domain; got {:?}",
		acme.contacts
	);
	assert_eq!(
		acme.domains,
		vec!["mail.example.org".to_string()],
		"acme.domains must include the hostname; got {:?}",
		acme.domains
	);
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		kinds.contains(&"acme"),
		"acme listener on port 80 must be written so HTTP-01 challenges reach the server; got {kinds:?}"
	);
	// The `[tls]` block points at the self-signed pair in `keys/`.
	// The certificate the authority issues lands at
	// `<data_dir>/acme/cert.pem` and takes over from there: the
	// renewal loop reloads the acceptor in memory, and
	// `crate::tls::served_tls` prefers the ACME pair on the next
	// start. The `[tls]` path must therefore stay a file that
	// exists: pointing it at the ACME path would leave a fresh
	// install with no certificate to serve until the authority
	// answered, and a certificate nobody vouches for in the
	// meantime.
	assert!(
		desired.tls.cert_file.contains("/keys/cert.pem"),
		"[tls].cert_file must point at the bootstrap pair in keys/ when ACME is on, so the \
		 server can serve a certificate before the authority answers; got {:?}",
		desired.tls.cert_file
	);
	assert!(
		desired.tls.key_file.contains("/keys/key.pem"),
		"[tls].key_file must point at the bootstrap pair in keys/ when ACME is on; got {:?}",
		desired.tls.key_file
	);
}

/// Loopback hostname with no `acme` answers section -> init does
/// not enable ACME. The loopback case covers both `localhost` (a
/// name) and a literal `127.0.0.1` (an IP) because either would
/// fail the ACME HTTP-01 challenge: Let's Encrypt needs to connect
/// to the host on port 80, and neither a loopback IP nor a name
/// only the operator knows has a public A record.
#[test]
fn build_config_leaves_acme_off_for_loopback_hostname() {
	let mut answers = answers_minimal();
	answers.hostname = "localhost".to_string();
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with localhost hostname");
	assert!(
		desired.acme.is_none(),
		"acme block must not be written for a loopback hostname; got {:?}",
		desired.acme
	);
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		!kinds.contains(&"acme"),
		"acme listener must not be written for a loopback hostname; got {kinds:?}"
	);
}

/// IP literal hostname -> ACME off. An IP literal cannot have an
/// A record pointing at the ACME challenge responder, and writing
/// `[acme]` would silently break renewal.
#[test]
fn build_config_leaves_acme_off_for_ip_literal_hostname() {
	let mut answers = answers_minimal();
	answers.hostname = "127.0.0.1".to_string();
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with ip literal");
	assert!(
		desired.acme.is_none(),
		"acme block must not be written for an ip-literal hostname"
	);
}

/// Reserved TLD (`.local`, `.internal`, `.test`, `.example`) ->
/// ACME off. These TLDs are not delegated in the public DNS, so
/// the ACME challenge would never resolve.
#[test]
fn build_config_leaves_acme_off_for_reserved_tld_hostname() {
	for reserved in [
		"mail.example.local",
		"mail.example.internal",
		"mail.example.test",
		"mail.example.example",
	] {
		let mut answers = answers_minimal();
		answers.hostname = reserved.to_string();
		let (cert, key, ed) = cert_key_ed();
		let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
		let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
			.unwrap_or_else(|error| panic!("build_config with {reserved}: {error}"));
		assert!(
			desired.acme.is_none(),
			"acme block must not be written for reserved-tld hostname {reserved}; got {:?}",
			desired.acme
		);
	}
}

/// Operator sets `acme.enabled = false` on a public hostname ->
/// ACME stays off. The opt-out is what an operator with an
/// out-of-band certificate (a frontman, an operator-issued cert)
/// uses; init must honour it and not write an `[acme]` block.
#[test]
fn build_config_honours_explicit_acme_disabled() {
	let mut answers = answers_minimal();
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(false),
		contact: None,
	});
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with acme.enabled = false");
	assert!(
		desired.acme.is_none(),
		"acme block must not be written when acme.enabled = false"
	);
	let kinds: Vec<&str> = desired.listeners.iter().map(|l| l.kind.as_str()).collect();
	assert!(
		!kinds.contains(&"acme"),
		"acme listener must not be written when acme.enabled = false"
	);
}

/// Operator sets `acme.contact` on a public hostname -> the contact
/// list carries the operator's address. The directory URL stays
/// on Let's Encrypt production; the contact is the only knob the
/// operator gets.
#[test]
fn build_config_honours_explicit_acme_contact() {
	let mut answers = answers_minimal();
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(true),
		contact: Some("mailto:ops@example.org".to_string()),
	});
	let (cert, key, ed) = cert_key_ed();
	let mail_addr: IpAddr = Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with acme.contact");
	let acme = desired
		.acme
		.as_ref()
		.expect("acme block must be written when acme.enabled = true");
	assert_eq!(
		acme.contacts,
		vec!["mailto:ops@example.org".to_string()],
		"acme.contacts must reflect the operator's contact override; got {:?}",
		acme.contacts
	);
}
