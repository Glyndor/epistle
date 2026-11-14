//! The state file reads back what it wrote and refuses what it does not know.

use super::*;

fn sample() -> DomainsFile {
	DomainsFile {
		seed_digest: "sha256:00".into(),
		domains: vec![
			HostedDomain::new("example.org"),
			HostedDomain {
				role: StoredRole::ReceiveOnly,
				enabled: false,
				dkim: Some(OwnKey {
					selector: "own1".into(),
					key_file: "/k/ed.pem".into(),
					rsa_selector: Some("ownrsa1".into()),
					rsa_key_file: Some("/k/rsa.pem".into()),
				}),
				srs_secret: Some("s".repeat(32)),
				..HostedDomain::new("other.example.org")
			},
		],
		aliases: [("alias.example.net".to_string(), "example.org".to_string())].into(),
	}
}

#[test]
fn what_is_written_reads_back_the_same() {
	let file = sample();
	let text = file.render().unwrap();
	assert!(text.starts_with("# The hosted domains"), "{text}");
	assert_eq!(DomainsFile::parse(&text).unwrap(), file);
}

#[test]
fn a_bare_entry_is_a_full_domain_that_is_switched_on() {
	let file = DomainsFile::parse("[[domain]]\nname = \"example.org\"\n").unwrap();
	assert_eq!(file.domains, [HostedDomain::new("example.org")]);
	assert_eq!(
		file.domains[0].effective_role(),
		crate::dns::skip::DomainRole::Full
	);
	assert!(file.seed_digest.is_empty());
}

#[test]
fn an_unknown_key_or_role_is_refused() {
	for text in [
		"[[domain]]\nname = \"example.org\"\ncolour = \"red\"\n",
		"[[domain]]\nname = \"example.org\"\nrole = \"disabled\"\n",
		"[[domain]]\nname = \"example.org\"\nenabled = \"yes\"\n",
		"domains = [\"example.org\"]\n",
	] {
		assert!(DomainsFile::parse(text).is_err(), "{text:?}");
	}
}

#[test]
fn lookups_ignore_ascii_case_and_surrounding_space() {
	let file = sample();
	assert!(file.domain(" EXAMPLE.org ").is_some());
	assert!(
		file.domain("example.org.").is_none(),
		"a trailing dot is another name"
	);
	assert_eq!(
		file.alias("ALIAS.example.net").map(|(key, _)| key.as_str()),
		Some("alias.example.net")
	);
}

#[test]
fn a_switched_off_domain_keeps_its_role() {
	let file = sample();
	let off = file.domain("other.example.org").unwrap();
	assert_eq!(off.role, StoredRole::ReceiveOnly);
	assert_eq!(off.effective_role(), crate::dns::skip::DomainRole::Disabled);
	assert_eq!(
		StoredRole::of(crate::dns::skip::DomainRole::Disabled),
		None,
		"switched off is not a role"
	);
}
