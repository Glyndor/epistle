//! Loading the configuration lays the state file over the configuration
//! file's lists, and only then.

use std::path::Path;

use super::super::tests::Fixture;

/// A DKIM key file under the data directory, and the `[dkim]` section that
/// signs with it.
fn dkim(fixture: &Fixture, name: &str) -> String {
	let (pem, _) = crate::dkim::generate_key().unwrap();
	let file = fixture.data_dir.join(format!("{name}.pem"));
	std::fs::write(&file, pem).unwrap();
	file.to_string_lossy().into_owned()
}

#[test]
fn without_a_state_file_the_configuration_file_is_the_state() {
	let fixture = Fixture::new("disabled_domains = [\"other.example.org\"]\n");
	let config = fixture.load();
	assert_eq!(config.domains, ["example.org", "other.example.org"]);
	assert_eq!(config.disabled_domains, ["other.example.org"]);
	assert!(config.adjusted.is_empty());
	assert!(fixture.state().is_none(), "loading writes nothing");
}

#[test]
fn the_state_file_replaces_every_list() {
	let fixture = Fixture::new("[domain_aliases]\n\"old.example.net\" = \"example.org\"\n");
	fixture.write_state(
		"[[domain]]\nname = \"example.org\"\nrole = \"send-only\"\n\
		 [[domain]]\nname = \"added.example\"\nrole = \"receive-only\"\nenabled = false\n\
		 [aliases]\n\"new.example.net\" = \"added.example\"\n",
	);
	let config = fixture.load();
	assert_eq!(config.domains, ["example.org", "added.example"]);
	assert_eq!(config.send_only_domains, ["example.org"]);
	assert_eq!(config.receive_only_domains, ["added.example"]);
	assert_eq!(config.disabled_domains, ["added.example"]);
	assert_eq!(config.domain_aliases.len(), 1);
	assert_eq!(config.domain_aliases["new.example.net"], "added.example");
	assert_eq!(
		config.domain_seed.domains,
		["example.org", "other.example.org"]
	);
}

#[test]
fn an_edit_of_the_configuration_file_after_the_seed_is_noted_and_ignored() {
	let fixture = Fixture::new("");
	assert!(super::super::edit::seed(&fixture.load()).unwrap());
	assert!(fixture.load().adjusted.is_empty(), "nothing changed yet");
	fixture.write_config(
		"[\"example.org\", \"other.example.org\", \"late.example\"]",
		"",
	);
	let config = fixture.load();
	assert_eq!(
		config.domains,
		["example.org", "other.example.org"],
		"the file wins"
	);
	let note = config.adjusted.join("\n");
	assert!(note.contains("epistle domain import"), "{note}");
	assert!(note.contains("domains.toml"), "{note}");
}

#[test]
fn entries_of_the_configuration_file_for_domains_the_state_drops_are_left_out() {
	let fixture = Fixture::new("");
	let default = dkim(&fixture, "default");
	let other = dkim(&fixture, "other");
	fixture.write_config(
		"[\"example.org\", \"other.example.org\"]",
		&format!(
			"domain_quotas = {{ \"other.example.org\" = 1000, \"example.org\" = 2000 }}\n\
			 [[srs_domain]]\nname = \"other.example.org\"\nsecret = \"{}\"\n\
			 [dkim]\nselector = \"s1\"\nkey_file = {default:?}\n\
			 [[dkim.domain]]\nname = \"other.example.org\"\nselector = \"o1\"\nkey_file = {other:?}\n",
			"x".repeat(40)
		),
	);
	fixture.write_state("[[domain]]\nname = \"example.org\"\n");
	let config = fixture.load();
	assert_eq!(config.domains, ["example.org"]);
	assert!(config.srs_domain.is_empty());
	assert!(config.dkim.as_ref().unwrap().domain.is_empty());
	assert_eq!(config.domain_quotas.len(), 1);
	assert_eq!(config.domain_quotas["example.org"], 2000);
}

#[test]
fn a_domain_of_the_state_file_brings_its_key_and_secret_unless_the_file_names_one() {
	let fixture = Fixture::new("");
	let default = dkim(&fixture, "default");
	let mine = dkim(&fixture, "mine");
	let theirs = dkim(&fixture, "theirs");
	fixture.write_config(
		"[\"example.org\"]",
		&format!(
			"[dkim]\nselector = \"s1\"\nkey_file = {default:?}\n\
			 [[dkim.domain]]\nname = \"example.org\"\nselector = \"cfg1\"\nkey_file = {theirs:?}\n"
		),
	);
	fixture.write_state(&format!(
		"[[domain]]\nname = \"example.org\"\nsrs_secret = \"{}\"\n\
		 [domain.dkim]\nselector = \"own1\"\nkey_file = {theirs:?}\n\
		 [[domain]]\nname = \"new.example\"\nsrs_secret = \"{}\"\n\
		 [domain.dkim]\nselector = \"own2\"\nkey_file = {mine:?}\n",
		"a".repeat(40),
		"b".repeat(40)
	));
	let config = fixture.load();
	let dkim = config.dkim.as_ref().unwrap();
	assert_eq!(
		dkim.override_for("example.org").unwrap().selector,
		"cfg1",
		"the configuration file's entry wins"
	);
	let new = dkim.override_for("new.example").expect("the file's key");
	assert_eq!(
		(new.selector.as_str(), Path::new(&mine)),
		("own2", new.key_file.as_path())
	);
	assert_eq!(
		config
			.srs_domain("new.example")
			.map(|entry| entry.secret.clone()),
		Some("b".repeat(40))
	);
}

#[test]
fn a_state_file_that_does_not_parse_stops_the_load() {
	let fixture = Fixture::new("");
	fixture.write_state("[[domain]]\nname = 1\n");
	let error = crate::config::Config::load(&fixture.config)
		.expect_err("refused")
		.to_string();
	assert!(error.contains("domains.toml"), "{error}");
	assert!(error.contains("epistle domain import"), "{error}");
}

#[test]
fn a_reload_from_the_seed_gives_the_configuration_file_back() {
	let fixture = Fixture::new("send_only_domains = [\"other.example.org\"]\n");
	let config = fixture.load();
	let file = config.domain_seed.file();
	let again = config.with_domains_file(&file);
	assert_eq!(again.domains, config.domains);
	assert_eq!(again.send_only_domains, config.send_only_domains);
	assert_eq!(again.disabled_domains, config.disabled_domains);
}
