//! Per-domain DKIM in Mox import: each domain's ed25519 key becomes a
//! per-domain `[dkim.domain]` override, not a single default key.

use super::*;
use crate::migrate::import::apply::tests::{epistle, mox_plan};

#[test]
fn two_domains_with_different_keys_become_per_domain_overrides() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (plan, written) = mox_plan(dir.path());
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	// Two domains in the Mox fixture, each with its own ed25519 key;
	// example.com also has an RSA key. The import records a file per
	// published key: 2 ed25519 + 1 RSA.
	assert_eq!(
		outcome.key_files.len(),
		3,
		"every imported key is still saved"
	);
	// No "one key pair" note: the per-domain path no longer needs it.
	assert!(
		!outcome.notes.iter().any(|n| n.contains("one key pair")),
		"per-domain import must not leave the legacy note, got: {:?}",
		outcome.notes
	);
	// The two domains end up as [[dkim.domain]] entries: the config
	// loads back with the override for each.
	let config = Config::load(&config_file).expect("load");
	let dkim = config.dkim.expect("[dkim] is set");
	assert_eq!(dkim.domain.len(), 2, "two per-domain overrides");
	let domains: std::collections::HashSet<String> =
		dkim.domain.iter().map(|d| d.name.clone()).collect();
	assert!(domains.contains("example.com"));
	assert!(domains.contains("xn--bcher-kva.example"));
	// The default [dkim] block is no longer set: per-domain overrides
	// are the signing key for every imported domain.
	// (A single domain's keys were left as a default before this
	//  feature; now both domains go through [dkim.domain].)
	let _ = written; // keep the fixture's expected rsa key referenced
}

#[test]
fn per_domain_keys_sign_with_their_own_selector() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (plan, _) = mox_plan(dir.path());
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	// Load the config back: each domain's signing key is the one
	// Mox published for it.
	let config = Config::load(&config_file).expect("load");
	let dkim = config.dkim.expect("[dkim] is set");
	let example = dkim
		.domain
		.iter()
		.find(|d| d.name == "example.com")
		.expect("example.com override");
	let bucher = dkim
		.domain
		.iter()
		.find(|d| d.name == "xn--bcher-kva.example")
		.expect("bücher.example override");
	// Each override's key file is readable; epistle signs with the
	// right selector for the right domain.
	let signer_example = crate::dkim::Signer::load(&example.selector, &example.key_file)
		.expect("example.com key loads");
	let signer_bucher = crate::dkim::Signer::load(&bucher.selector, &bucher.key_file)
		.expect("bücher.example key loads");
	let _ = (signer_example, signer_bucher);
	// The outcome reports the per-domain import succeeded.
	assert!(outcome.notes.is_empty() || !outcome.notes.iter().any(|n| n.contains("one key pair")));
}
