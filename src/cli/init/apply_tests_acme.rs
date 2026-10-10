//! ACME auto-enable for public hostnames.
//!
//! The `init` answers file gets three knobs: a per-answers `acme`
//! section with `enabled` and `contact`. When `enabled` is unset and
//! the hostname is public (a real DNS name, not `localhost` / `127.0.0.1`
//! / `.local` / `.internal` / `.test` / `.example`), init enables ACME
//! automatically: it writes an `[acme]` block pointing at Let's
//! Encrypt production, the `acme` listener on port 80, and a
//! postmaster contact at the first configured domain. An operator
//! who wants to opt out sets `acme.enabled = false` or runs init
//! against a private hostname, where ACME is off by default.
//!
//! Sister to `apply_tests_implicit_tls.rs` because both files cover
//! what `init` writes into the config and how the compose file
//! publishes the ports; together they own the public-install shape.

use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use serde_json::Value;

use super::Answers;
use super::apply;
use super::apply_config;
use crate::cli::init::answers::{Mode, Services};

fn answers_minimal() -> Answers {
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
		image: None,
		acme: None,
	}
}

fn cert_key_ed() -> (PathBuf, PathBuf, PathBuf) {
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
	// The `[tls]` block has to point at the ACME cert / key paths
	// so the server can boot off the self-signed bootstrap cert
	// init writes there. Pointing at `keys/cert.pem` instead would
	// mean the renewal loop writes a different file the server
	// never reads from, and the SMTP acceptor's hot reload would
	// never pick up the new cert.
	assert!(
		desired.tls.cert_file.contains("/acme/cert.pem"),
		"[tls].cert_file must point at the ACME cert path when ACME is on, so the renewal \
		 loop's hot reload picks up the issued cert; got {:?}",
		desired.tls.cert_file
	);
	assert!(
		desired.tls.key_file.contains("/acme/key.pem"),
		"[tls].key_file must point at the ACME key path when ACME is on; got {:?}",
		desired.tls.key_file
	);
	// The path init hands back to `build_config` is the keys/
	// path (where init originally generated the self-signed
	// cert). With ACME on, init needs to copy that material to
	// the ACME path so the server has a cert to load at startup.
	// A regression that kept writing only at keys/ would leave
	// the server failing to start when [tls] cert_file points at
	// the ACME path and no ACME cert has been issued yet.
	// This test does not exercise the file-copy path; the full
	// apply path does, in apply.rs itself.
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

/// When ACME is on, the compose file's `mail.ports:` array
/// publishes port 80 alongside the other mail ports. Port 80 is
/// the ACME HTTP-01 challenge responder; without the publish, the
/// challenge never reaches the container and certificate issuance
/// silently fails.
#[test]
fn compose_publishes_acme_port_80_when_acme_is_on() {
	use crate::cli::init::compose::{render, stack_answers};
	let mut answers = stack_answers();
	// The stack helper already names a public-ish hostname; force
	// acme on so the test does not depend on the heuristic.
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(true),
		contact: None,
	});
	let value: Value = render(&answers, true);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		ports.contains(&"80:80".to_string()),
		"port 80 must be published when ACME is on so the HTTP-01 challenge can reach the responder; got {ports:?}"
	);
}

/// When ACME is on, init copies the self-signed bootstrap cert
/// (the material `apply_keys::ensure_self_signed_cert` writes next
/// to the other keys) to `<data_dir>/acme/cert.pem` and the
/// matching key to `<data_dir>/acme/key.pem`. The renewal loop
/// in `crate::acme::renew` overwrites both files in place; until
/// the first renewal lands, the server has to be able to load
/// the bootstrap copies to start. A regression that wrote the
/// cert only at the keys/ path would leave the server failing to
/// start because the [tls] section (the test above) points at
/// the ACME path and no ACME cert has been issued yet.
#[test]
fn apply_copies_the_bootstrap_cert_to_the_acme_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// Public hostname: ACME auto-enables on a fresh install.
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed with ACME auto-enabled; got {:?}",
		outcome.error
	);
	let acme_dir = data_dir.join("acme");
	let acme_cert = acme_dir.join("cert.pem");
	let acme_key = acme_dir.join("key.pem");
	for path in [&acme_cert, &acme_key] {
		assert!(
			path.exists(),
			"apply must write the bootstrap {} at the ACME target; file is missing",
			path.display()
		);
		let bytes = std::fs::read(path).expect("read bootstrap cert");
		assert!(
			!bytes.is_empty(),
			"bootstrap {} must not be empty",
			path.display()
		);
	}
	// The bootstrap copies must be byte-identical to the
	// material at the keys/ path; the renewal loop overwrites
	// in place, so any drift between the two would mean the
	// server is loading a cert init never produced.
	let keys_cert = data_dir.join("keys").join("cert.pem");
	let keys_key = data_dir.join("keys").join("key.pem");
	assert_eq!(
		std::fs::read(&acme_cert).expect("read acme cert"),
		std::fs::read(&keys_cert).expect("read keys cert"),
		"the bootstrap cert init copies to <data_dir>/acme/cert.pem must be byte-identical to \
		 the material at <data_dir>/keys/cert.pem"
	);
	assert_eq!(
		std::fs::read(&acme_key).expect("read acme key"),
		std::fs::read(&keys_key).expect("read keys key"),
		"the bootstrap key init copies to <data_dir>/acme/key.pem must be byte-identical to \
		 the material at <data_dir>/keys/key.pem"
	);
}

/// When ACME is off, init does not create `<data_dir>/acme/` at
/// all. The keys/ path is what the server loads; the ACME path is
/// only relevant when ACME is on.
#[test]
fn apply_does_not_create_the_acme_directory_when_acme_is_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.hostname = "mail.example.local".to_string();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed with ACME off; got {:?}",
		outcome.error
	);
	let acme_dir = data_dir.join("acme");
	assert!(
		!acme_dir.exists(),
		"apply must not create <data_dir>/acme when ACME is off; got {}",
		acme_dir.display()
	);
}

/// When ACME is off, port 80 is not published. The compose writer
/// derives the published-port list from the listener set init just
/// wrote, so the absence of the `acme` listener in the config is
/// what keeps 80 out of the publish map. A regression that always
/// published 80 would forward traffic to a closed socket for every
/// install that runs without ACME.
#[test]
fn compose_does_not_publish_acme_port_80_when_acme_is_off() {
	use crate::cli::init::compose::{render, stack_answers};
	let mut answers = stack_answers();
	answers.hostname = "mail.example.local".to_string();
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(false),
		contact: None,
	});
	let value: Value = render(&answers, true);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		!ports.contains(&"80:80".to_string()),
		"port 80 must not be published when ACME is off; got {ports:?}"
	);
}
