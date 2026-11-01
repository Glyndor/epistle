use super::*;
use std::io::Write;

pub(super) fn fresh_signer(selector: &str) -> Arc<Signer> {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(pem.as_bytes()).expect("write");
	let signer = Signer::load(selector, file.path()).expect("load");
	Arc::new(signer)
}

#[test]
fn picks_the_override_for_a_listed_domain() {
	let default = ReloadableSigner::new(fresh_signer("default-sel"));
	let overrides = vec![DomainSigner {
		domain: "example.org".to_string(),
		signer: fresh_signer("per-sel"),
	}];
	let signer = PerDomainSigner::new(default, overrides);
	let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
	let header = signer.sign("example.org", raw).expect("signs");
	assert!(
		header.contains("s=per-sel;"),
		"override selector must be the one signed with, got {header}"
	);
}

#[test]
fn falls_back_to_the_default_for_an_unlisted_domain() {
	let default = ReloadableSigner::new(fresh_signer("default-sel"));
	let overrides = vec![DomainSigner {
		domain: "example.org".to_string(),
		signer: fresh_signer("per-sel"),
	}];
	let signer = PerDomainSigner::new(default, overrides);
	let raw = b"From: a@elsewhere.example\r\nSubject: x\r\n\r\nbody\r\n";
	let header = signer.sign("elsewhere.example", raw).expect("signs");
	assert!(
		header.contains("s=default-sel;"),
		"unlisted domain must sign with the default, got {header}"
	);
}

#[test]
fn matches_overrides_case_insensitively() {
	let default = ReloadableSigner::new(fresh_signer("default-sel"));
	let overrides = vec![DomainSigner {
		domain: "example.org".to_string(),
		signer: fresh_signer("per-sel"),
	}];
	let signer = PerDomainSigner::new(default, overrides);
	let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
	let header = signer.sign("EXAMPLE.ORG", raw).expect("signs");
	assert!(
		header.contains("s=per-sel;"),
		"override lookup must be case-insensitive, got {header}"
	);
}

#[test]
fn reload_replaces_only_the_default_signer() {
	let default = ReloadableSigner::new(fresh_signer("default-sel"));
	let overrides = vec![DomainSigner {
		domain: "example.org".to_string(),
		signer: fresh_signer("per-sel"),
	}];
	let signer = PerDomainSigner::new(default.clone(), overrides);
	default.reload(fresh_signer("default-2"));
	let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
	let listed = signer.sign("example.org", raw).expect("signs");
	assert!(
		listed.contains("s=per-sel;"),
		"per-domain override must be unaffected by default reload, got {listed}"
	);
	let raw = b"From: a@other.example\r\nSubject: x\r\n\r\nbody\r\n";
	let other = signer.sign("other.example", raw).expect("signs");
	assert!(
		other.contains("s=default-2;"),
		"default reload must propagate to the default signer, got {other}"
	);
}
