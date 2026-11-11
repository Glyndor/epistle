//! A secret field added to the configuration must have an entry in the
//! registry, so the recovery procedure cannot forget a new kind of secret.

use std::collections::BTreeSet;

use super::source::config_secret_fields;
use crate::cli::rotate::registry::entries;

/// Fields whose name looks like a secret and that are not one, each with the
/// reason. A new line here needs a reason a reviewer can check.
const NOT_SECRETS: &[(&str, &str)] = &[
	("Oauth.public_key", "the public half of the signing key"),
	("Dns.key_name", "the name of a TSIG key, not its secret"),
	(
		"S3BlobConfig.access_key_id",
		"the identifier half of the S3 key pair; the secret half has its own entry",
	),
];

fn claimed() -> Vec<&'static str> {
	entries()
		.flat_map(|entry| entry.config_fields.iter().copied())
		.collect()
}

#[test]
fn every_secret_field_of_the_configuration_has_an_entry() {
	let claimed: BTreeSet<&str> = claimed().into_iter().collect();
	let excused: BTreeSet<&str> = NOT_SECRETS.iter().map(|(field, _)| *field).collect();
	let missing: Vec<String> = config_secret_fields()
		.into_iter()
		.filter(|field| !claimed.contains(field.as_str()) && !excused.contains(field.as_str()))
		.collect();
	assert!(
		missing.is_empty(),
		"configuration fields that look like secrets and no registry entry names: {missing:#?}\n\
		 add the kind to src/cli/rotate/registry (config_fields), with how it is rotated and \
		 revoked, or list the field in NOT_SECRETS with the reason it is not a secret"
	);
}

#[test]
fn no_entry_names_a_field_the_configuration_does_not_have() {
	let found: BTreeSet<String> = config_secret_fields().into_iter().collect();
	let stale: Vec<&str> = claimed()
		.into_iter()
		.filter(|field| !found.contains(*field))
		.collect();
	assert!(
		stale.is_empty(),
		"registry fields that do not exist: {stale:#?}"
	);
}

#[test]
fn a_field_belongs_to_one_entry_and_is_not_also_excused() {
	let mut seen = BTreeSet::new();
	let doubled: Vec<&str> = claimed()
		.into_iter()
		.filter(|field| !seen.insert(*field))
		.collect();
	assert!(doubled.is_empty(), "claimed by two entries: {doubled:#?}");
	let both: Vec<&str> = NOT_SECRETS
		.iter()
		.map(|(field, _)| *field)
		.filter(|field| seen.contains(field))
		.collect();
	assert!(both.is_empty(), "claimed and excused: {both:#?}");
	let gone: BTreeSet<String> = config_secret_fields().into_iter().collect();
	let stale: Vec<&str> = NOT_SECRETS
		.iter()
		.map(|(field, _)| *field)
		.filter(|field| !gone.contains(*field))
		.collect();
	assert!(
		stale.is_empty(),
		"NOT_SECRETS fields that do not exist: {stale:#?}"
	);
}
