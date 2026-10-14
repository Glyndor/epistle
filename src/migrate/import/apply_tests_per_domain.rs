//! Per-domain DKIM in a Mox import: every imported domain keeps signing
//! with the key Mox published for it, and the configuration it leaves
//! loads and starts like any other.

use std::sync::Arc;

use super::*;
use crate::dkim::{DomainSigner, PerDomainSigner, ReloadableSigner, Signer};
use crate::migrate::import::apply::tests::{epistle, mox_plan};

const BUCHER: &str = "xn--bcher-kva.example";

/// The public record of the key in Mox's PEM `source`, which is the record
/// Mox had published for that selector.
fn mox_record(source: &str) -> String {
	let normalized = crate::migrate::import::keys::normalize(source, None)
		.unwrap_or_else(|_| panic!("the Mox key decodes"));
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mox.pem");
	std::fs::write(
		&path,
		crate::migrate::import::keys::to_pem(&normalized.pkcs8).as_bytes(),
	)
	.expect("write");
	Signer::load("mox", &path)
		.unwrap_or_else(|_| panic!("the Mox key loads"))
		.dns_record_value()
}

/// The signer `serve` builds from `dkim`, without the rotation state.
fn server_signer(dkim: &crate::config::Dkim) -> PerDomainSigner {
	let default = Signer::load(&dkim.selector, &dkim.key_file)
		.unwrap_or_else(|_| panic!("the default key loads"));
	let overrides = dkim
		.domain
		.iter()
		.map(|entry| DomainSigner {
			domain: entry.name.to_ascii_lowercase(),
			signer: Arc::new(
				Signer::load(&entry.selector, &entry.key_file)
					.unwrap_or_else(|_| panic!("the override key loads")),
			),
		})
		.collect();
	PerDomainSigner::new(ReloadableSigner::new(Arc::new(default)), overrides)
}

/// Sign a message for `domain` and verify it against `record` published
/// under the selector the signature names.
fn verifies_with(signer: &PerDomainSigner, domain: &str, record: &str) -> bool {
	let raw = format!("From: a@{domain}\r\nSubject: x\r\n\r\nbody\r\n");
	let header = signer.sign(domain, raw.as_bytes()).expect("signs");
	let signed = format!("{header}{raw}");
	let fields = crate::dkim::test_support::signature_fields(signed.as_bytes());
	let ed = fields
		.iter()
		.find(|(_, _, a)| a == "ed25519-sha256")
		.expect("an ed25519 signature");
	assert_eq!(ed.1, domain, "d= is the domain signed for");
	let dns = crate::dkim::test_support::KeyDns(
		[(
			format!("{}._domainkey.{domain}", ed.0),
			vec![record.to_string()],
		)]
		.into(),
	);
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	runtime
		.block_on(crate::dkim::verify_message(&dns, signed.as_bytes()))
		.iter()
		.any(|result| result.outcome == crate::dkim::DkimOutcome::Pass)
}

#[test]
fn a_fresh_import_signs_every_domain_with_the_key_mox_published_for_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (plan, written) = mox_plan(dir.path());
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	assert_eq!(outcome.key_files.len(), 3, "every key is saved");
	let dkim = Config::load(&config_file)
		.expect("the imported configuration loads")
		.dkim
		.expect("[dkim] is set");
	// The first domain's pair is the default, so a domain added later
	// signs too; the other domain gets its own key as an override.
	assert_eq!(dkim.selector, "2024a");
	assert_eq!(dkim.rsa_selector.as_deref(), Some("2024b"));
	let names: Vec<&str> = dkim.domain.iter().map(|d| d.name.as_str()).collect();
	assert_eq!(names, [BUCHER]);
	let signer = server_signer(&dkim);
	assert!(verifies_with(
		&signer,
		"example.com",
		&mox_record(&written.ed25519)
	));
	assert!(verifies_with(&signer, BUCHER, &mox_record(&written.other)));
	assert!(
		!verifies_with(&signer, BUCHER, &mox_record(&written.ed25519)),
		"bücher.example must not sign with example.com's key"
	);
	assert!(
		!outcome
			.notes
			.iter()
			.any(|n| n.contains("no ed25519 DKIM key")),
		"no imported domain is left signing with another domain's key"
	);
}

#[test]
fn an_existing_default_stays_and_each_imported_domain_gets_its_own_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(
		dir.path(),
		"[dkim]\nselector = \"local\"\nkey_file = \"/etc/epistle/local.pem\"\n",
	);
	let (plan, _) = mox_plan(dir.path());
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	apply(&plan, prepared, &Passwords::Reset).expect("apply");
	let dkim = Config::load(&config_file)
		.expect("the imported configuration loads")
		.dkim
		.expect("[dkim] is set");
	assert_eq!(dkim.selector, "local", "the operator's default is kept");
	assert_eq!(
		dkim.key_file,
		std::path::PathBuf::from("/etc/epistle/local.pem")
	);
	let mut overrides: Vec<(&str, &str, Option<&str>)> = dkim
		.domain
		.iter()
		.map(|d| {
			(
				d.name.as_str(),
				d.selector.as_str(),
				d.rsa_selector.as_deref(),
			)
		})
		.collect();
	overrides.sort();
	assert_eq!(
		overrides,
		[
			("example.com", "2024a", Some("2024b")),
			(BUCHER, "2024a", None),
		]
	);
}
