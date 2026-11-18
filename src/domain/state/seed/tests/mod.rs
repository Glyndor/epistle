//! The seed turns the configuration file's lists into a state file, and its
//! digest moves only when those lists do.

use super::super::tests::Fixture;
use super::*;

const LISTS: &str = "disabled_domains = [\"other.example.org\"]\n\
	send_only_domains = [\"Example.org\"]\n\
	[domain_aliases]\n\"Alias.example.net\" = \"example.org\"\n";

#[test]
fn the_seed_file_holds_what_the_configuration_file_declares() {
	let fixture = Fixture::new(LISTS);
	let config = fixture.load();
	let file = config.domain_seed.file();
	assert_eq!(file.names(), ["example.org", "other.example.org"]);
	let example = file.domain("example.org").unwrap();
	assert_eq!(
		(example.role, example.enabled),
		(StoredRole::SendOnly, true)
	);
	let other = file.domain("other.example.org").unwrap();
	assert_eq!((other.role, other.enabled), (StoredRole::Full, false));
	assert_eq!(
		file.aliases.get("alias.example.net").map(String::as_str),
		Some("example.org")
	);
	assert_eq!(file.seed_digest, config.domain_seed.digest());
}

#[test]
fn the_digest_ignores_order_and_case_and_follows_every_list() {
	let fixture = Fixture::new(LISTS);
	let digest = fixture.load().domain_seed.digest();
	fixture.write_config(
		"[\"OTHER.example.org\", \"example.org\"]",
		&LISTS.replace("Example.org", "example.ORG"),
	);
	assert_eq!(fixture.load().domain_seed.digest(), digest);
	for changed in [
		LISTS.replace("disabled_domains = [\"other.example.org\"]", ""),
		LISTS.replace("send_only_domains", "receive_only_domains"),
		LISTS.replace("Alias.example.net", "alias2.example.net"),
	] {
		fixture.write_config("[\"example.org\", \"other.example.org\"]", &changed);
		assert_ne!(fixture.load().domain_seed.digest(), digest, "{changed}");
	}
}
