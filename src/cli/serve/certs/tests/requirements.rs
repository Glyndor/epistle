//! The certificates role starts only with what it can renew with.

use super::*;

#[test]
fn a_configuration_without_acme_is_refused_by_name() {
	let dir = tempfile::tempdir().expect("directory");
	let error = requirements(&config(dir.path(), None, true)).expect_err("no [acme]");
	assert!(error.contains("has no [acme]"), "{error}");
}

#[test]
fn http01_is_refused_because_mail_owns_its_port() {
	let dir = tempfile::tempdir().expect("directory");
	let error = requirements(&config(dir.path(), Some("http-01"), true)).expect_err("http-01");
	assert!(
		error.contains("answers only the dns-01 challenge"),
		"{error}"
	);
	assert!(error.contains("\"http-01\""), "{error}");
}

#[test]
fn tls_alpn01_is_refused_because_mail_owns_its_port() {
	let dir = tempfile::tempdir().expect("directory");
	let mut config = config(dir.path(), Some("dns-01"), true);
	if let Some(acme) = config.acme.as_mut() {
		acme.challenge = crate::config::AcmeChallenge::TlsAlpn01;
	}
	let error = requirements(&config).expect_err("tls-alpn-01");
	assert!(error.contains("\"tls-alpn-01\""), "{error}");
}

#[test]
fn dns01_without_a_provider_is_refused_by_name() {
	let dir = tempfile::tempdir().expect("directory");
	let mut config = config(dir.path(), Some("dns-01"), true);
	config.dns = crate::config::DnsProviders::default();
	let error = requirements(&config).expect_err("no [dns]");
	assert!(error.contains("has no [dns] provider"), "{error}");
}

/// The shape every refusal above sits just outside of.
#[test]
fn dns01_with_a_provider_is_accepted() {
	let dir = tempfile::tempdir().expect("directory");
	let config = config(dir.path(), Some("dns-01"), true);
	let acme = requirements(&config).expect("dns-01 with [dns]");
	assert_eq!(acme.domains, ["mail.example.org"]);
}
