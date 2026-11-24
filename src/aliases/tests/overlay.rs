//! The state file laid over the configuration file: the seed, the overlay,
//! the note when the configuration file moved on, and the file that does not
//! load.

use crate::aliases::edit::{self, NewAlias};
use crate::aliases::overlay::digest;
use crate::aliases::{AliasesFile, Change, Origin, path};
use crate::config::Config;

const SEEDED: &str =
	"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n";

fn setup(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("dir");
	let data = dir.path().join("data");
	std::fs::create_dir(&data).expect("data dir");
	let file = dir.path().join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
			data.canonicalize().expect("canonical")
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	(dir, file)
}

fn load(file: &std::path::Path) -> Config {
	Config::load(file).expect("loads")
}

fn add(address: &str) -> Change {
	Change::Add(NewAlias {
		address: address.into(),
		members: vec!["alice@example.org".into()],
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	})
}

#[test]
fn without_a_state_file_the_configuration_file_is_the_state() {
	let (_dir, file) = setup(SEEDED);
	let config = load(&file);
	assert_eq!(config.alias.len(), 1);
	assert_eq!(config.alias_seed.as_ref().map(Vec::len), Some(1));
	assert!(!path(&config.data_dir).exists());
}

#[test]
fn the_first_write_copies_the_seed_and_the_file_then_wins() {
	let (_dir, file) = setup(SEEDED);
	let config = load(&file);
	edit::commit(&config, &add("ops@example.org"), &Origin::Operator).expect("add");
	let state = AliasesFile::read(&path(&config.data_dir))
		.expect("read")
		.expect("written");
	let addresses: Vec<&str> = state.aliases.iter().map(|a| a.address.as_str()).collect();
	assert_eq!(addresses, ["team@example.org", "ops@example.org"]);
	assert_eq!(state.seed_digest, digest(&config.alias));
	// A new load sees the file, and the configuration file is not written.
	let reloaded = load(&file);
	assert_eq!(reloaded.alias.len(), 2);
	assert!(
		!std::fs::read_to_string(&file)
			.expect("config")
			.contains("ops@example.org")
	);
}

#[test]
fn a_configuration_file_edited_after_the_seed_is_reported_and_not_applied() {
	let (dir, file) = setup(SEEDED);
	edit::commit(&load(&file), &add("ops@example.org"), &Origin::Operator).expect("add");
	// The operator edits the table in the configuration file afterwards.
	let text = std::fs::read_to_string(&file).expect("config");
	std::fs::write(
		&file,
		text.replace(
			"members = [\"alice@example.org\"]",
			"members = [\"bob@example.org\"]",
		),
	)
	.expect("rewrite");
	let config = load(&file);
	assert_eq!(config.alias.len(), 2, "the state file still wins");
	assert_eq!(config.alias[0].members, ["alice@example.org"]);
	assert!(
		config
			.adjusted
			.iter()
			.any(|note| note.contains("[[alias]]") && note.contains("address-aliases.toml")),
		"{:?}",
		config.adjusted
	);
	drop(dir);
}

#[test]
fn a_state_file_that_does_not_parse_stops_the_load() {
	let (_dir, file) = setup(SEEDED);
	let config = load(&file);
	std::fs::write(path(&config.data_dir), "[[alias]\n").expect("write");
	let error = Config::load(&file).expect_err("refused");
	assert!(
		error.to_string().contains("address-aliases.toml"),
		"{error}"
	);
}

#[test]
fn a_state_file_with_an_alias_that_does_not_validate_stops_the_load() {
	let (_dir, file) = setup(SEEDED);
	let config = load(&file);
	std::fs::write(
		path(&config.data_dir),
		"[[alias]]\naddress = \"team@example.org\"\nmembers = []\n",
	)
	.expect("write");
	assert!(Config::load(&file).is_err());
}

#[test]
fn the_current_aliases_are_read_from_disk_and_not_from_the_snapshot() {
	let (_dir, file) = setup(SEEDED);
	let stale = load(&file);
	edit::commit(&stale, &add("ops@example.org"), &Origin::Operator).expect("add");
	assert_eq!(stale.alias.len(), 1, "the snapshot did not move");
	assert_eq!(crate::aliases::current(&stale).len(), 2);
}

#[test]
fn the_digest_ignores_order_and_case() {
	let (_dir, file) = setup(
		"[[alias]]\naddress = \"B@example.org\"\nmembers = [\"x@example.org\", \"y@example.org\"]\n\n[[alias]]\naddress = \"a@example.org\"\nmembers = [\"x@example.org\"]\n",
	);
	let config = load(&file);
	let mut shuffled = config.alias.clone();
	shuffled.reverse();
	shuffled[1].members.reverse();
	assert_eq!(digest(&config.alias), digest(&shuffled));
	shuffled[0].members.push("z@example.org".into());
	assert_ne!(digest(&config.alias), digest(&shuffled));
}
