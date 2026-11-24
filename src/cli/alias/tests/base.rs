//! `epistle alias`: list/show/add/remove flow on a fixture config.

use std::io::Write;
use std::path::Path;

use super::super::helpers::find_alias;
use super::*;
use crate::aliases::edit::NewAlias;
use crate::aliases::{AliasError, Change, Origin, edit};
use crate::config::Config;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

#[test]
fn list_writes_every_alias_with_state_and_visibility() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\", \"bob@example.org\"]\nsenders = [\"ceo@example.org\"]\nlist_id = \"team.example.org\"\nhidden = false\n\n[[alias]]\naddress = \"ops@example.org\"\nmembers = [\"alice@example.org\"]\n",
	);
	let config = load(file.path());
	let mut out = Vec::new();
	list(&config, false, &mut out).expect("list must succeed");
	let text = String::from_utf8(out).unwrap();
	assert!(
		text.contains("team@example.org"),
		"list must include the alias: {text}"
	);
	assert!(
		text.contains("ops@example.org"),
		"list must include all aliases: {text}"
	);
	assert!(text.contains("enabled"), "list must mark state: {text}");
}

#[test]
fn list_json_emits_a_parseable_array_with_enabled_field() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut out = Vec::new();
	list(&config, true, &mut out).expect("list must succeed");
	let parsed: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	let rows = parsed.as_array().expect("array");
	assert_eq!(rows.len(), 1);
	let row = &rows[0];
	assert_eq!(row["address"], "team@example.org");
	assert_eq!(row["enabled"], true);
	assert_eq!(row["hidden"], true);
}

#[test]
fn show_writes_every_field_for_one_alias() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\", \"bob@example.org\"]\nsenders = [\"ceo@example.org\"]\nlist_id = \"team.example.org\"\nhidden = false\n",
	);
	let config = load(file.path());
	let mut out = Vec::new();
	show(&config, "team@example.org", false, &mut out).expect("show must succeed");
	let text = String::from_utf8(out).unwrap();
	for needle in [
		"address\tteam@example.org",
		"members\talice@example.org,bob@example.org",
		"senders\tceo@example.org",
		"hidden\tfalse",
		"list_id\tteam.example.org",
		"enabled\ttrue",
	] {
		assert!(
			text.contains(needle),
			"show must contain {needle:?}\n--- got ---\n{text}"
		);
	}
}

#[test]
fn show_with_no_senders_prints_any_member() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut out = Vec::new();
	show(&config, "team@example.org", false, &mut out).expect("show must succeed");
	let text = String::from_utf8(out).unwrap();
	assert!(
		text.contains("any member"),
		"show must report the empty senders case"
	);
}

#[test]
fn find_alias_matches_case_insensitively() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	assert!(find_alias(&config, "TEAM@example.org").is_some());
	assert!(find_alias(&config, "missing@example.org").is_none());
}

/// Commit `change` for the operator against the configuration at `path`.
fn commit(path: &Path, change: Change) -> Result<edit::Committed, AliasError> {
	edit::commit(&load(path), &change, &Origin::Operator)
}

fn new_alias(address: &str, members: &[&str]) -> NewAlias {
	NewAlias {
		address: address.to_string(),
		members: members.iter().map(|member| member.to_string()).collect(),
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	}
}

#[test]
fn add_writes_a_new_alias_with_optional_fields() {
	let (dir, file) = fixture("");
	let new = NewAlias {
		senders: vec!["ceo@example.org".to_string()],
		list_id: Some("team.example.org".to_string()),
		hidden: false,
		..new_alias(
			"team@example.org",
			&["alice@example.org", "bob@example.org"],
		)
	};
	let done = commit(file.path(), Change::Add(new)).expect("add must succeed");
	assert!(done.changed);
	let state = std::fs::read_to_string(dir.path().join("address-aliases.toml")).unwrap();
	for needle in [
		"team@example.org",
		"alice@example.org",
		"ceo@example.org",
		"team.example.org",
		"hidden = false",
	] {
		assert!(
			state.contains(needle),
			"the state file lacks {needle}: {state}"
		);
	}
	let config = load(file.path());
	assert_eq!(config.alias.len(), 1);
	assert_eq!(config.alias[0].address, "team@example.org");
	let text = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		!text.contains("team@example.org"),
		"the configuration file is not written"
	);
}

/// An alias address is an address, not an account name: a dot in the local
/// part is fine, and the alias is found in any case.
#[test]
fn add_accepts_a_dotted_alias_address() {
	let (_dir, file) = fixture("");
	let new = new_alias("Name.Surname@example.org", &["alice.jones@example.org"]);
	commit(file.path(), Change::Add(new)).expect("add must succeed");
	let config = load(file.path());
	assert!(find_alias(&config, "name.surname@EXAMPLE.org").is_some());
}

#[test]
fn add_refuses_a_duplicate_alias() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let err = commit(
		file.path(),
		Change::Add(new_alias("team@example.org", &["bob@example.org"])),
	)
	.unwrap_err();
	assert_eq!(
		err,
		AliasError::Exists("alias team@example.org already exists".into())
	);
}

#[test]
fn add_refuses_an_alias_address_outside_configured_domains() {
	let (_dir, file) = fixture("");
	let err = commit(
		file.path(),
		Change::Add(new_alias("team@other.org", &["alice@example.org"])),
	)
	.unwrap_err();
	assert_eq!(
		err.to_string(),
		"alias address: other.org is not a domain this server handles"
	);
}

#[test]
fn add_refuses_an_address_used_by_a_static_account() {
	// argon2id PHC string is required by the loader; the test never
	// authenticates the account, so any well-formed PHC will load.
	let (_dir, file) = fixture(
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n",
	);
	let err = commit(
		file.path(),
		Change::Add(new_alias("alice@example.org", &["bob@example.org"])),
	)
	.unwrap_err();
	assert!(
		err.to_string().contains("already used by an account"),
		"unexpected message: {err}"
	);
}

#[test]
fn remove_drops_an_existing_alias() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n\n[[alias]]\naddress = \"ops@example.org\"\nmembers = [\"alice@example.org\"]\n",
	);
	commit(
		file.path(),
		Change::Remove {
			address: "team@example.org".to_string(),
		},
	)
	.expect("remove must succeed");
	let addresses: Vec<String> = load(file.path())
		.alias
		.iter()
		.map(|alias| alias.address.clone())
		.collect();
	assert_eq!(addresses, ["ops@example.org"]);
}

#[test]
fn remove_refuses_an_unknown_alias() {
	let (_dir, file) = fixture("");
	let err = commit(
		file.path(),
		Change::Remove {
			address: "team@example.org".to_string(),
		},
	)
	.unwrap_err();
	assert_eq!(
		err,
		AliasError::NotFound("alias team@example.org not found".into())
	);
}

const TEAM: &str = "[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n";

#[test]
fn member_add_appends_to_the_alias_members_list() {
	let (_dir, file) = fixture(TEAM);
	commit(
		file.path(),
		Change::MemberAdd {
			address: "team@example.org".to_string(),
			member: "bob@example.org".to_string(),
		},
	)
	.expect("add member must succeed");
	assert_eq!(
		load(file.path()).alias[0].members,
		vec![
			"alice@example.org".to_string(),
			"bob@example.org".to_string()
		]
	);
}

#[test]
fn member_remove_drops_the_member_and_keeps_one() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\", \"bob@example.org\"]\n",
	);
	commit(
		file.path(),
		Change::MemberRemove {
			address: "team@example.org".to_string(),
			member: "bob@example.org".to_string(),
		},
	)
	.expect("remove member must succeed");
	assert_eq!(
		load(file.path()).alias[0].members,
		vec!["alice@example.org".to_string()]
	);
}

#[test]
fn member_remove_refuses_to_leave_an_alias_empty() {
	let (_dir, file) = fixture(TEAM);
	let err = commit(
		file.path(),
		Change::MemberRemove {
			address: "team@example.org".to_string(),
			member: "alice@example.org".to_string(),
		},
	)
	.unwrap_err();
	assert!(
		err.to_string().contains("no members"),
		"unexpected message: {err}"
	);
}

#[test]
fn sender_add_and_remove_round_trip() {
	let (_dir, file) = fixture(TEAM);
	commit(
		file.path(),
		Change::SenderAdd {
			address: "team@example.org".to_string(),
			sender: "ceo@example.org".to_string(),
		},
	)
	.expect("add sender must succeed");
	assert_eq!(
		load(file.path()).alias[0].senders,
		vec!["ceo@example.org".to_string()]
	);
	commit(
		file.path(),
		Change::SenderRemove {
			address: "team@example.org".to_string(),
			sender: "ceo@example.org".to_string(),
		},
	)
	.expect("remove sender must succeed");
	assert!(load(file.path()).alias[0].senders.is_empty());
}

#[test]
fn an_alias_address_and_its_people_are_checked_as_before() {
	let (_dir, file) = fixture("");
	let refused = |address: &str, members: &[&str]| {
		commit(file.path(), Change::Add(new_alias(address, members)))
			.expect_err("refused")
			.to_string()
	};
	assert_eq!(
		refused("not-an-email", &["alice@example.org"]),
		"alias address: not-an-email has no @"
	);
	assert_eq!(
		refused("team@example.org", &["bad"]),
		"member address: bad has no @"
	);
	assert_eq!(
		refused("team@example.org", &[]),
		"alias team@example.org has no members"
	);
}

#[test]
fn dry_run_prints_a_diff_and_does_not_write() {
	let (dir, file) = fixture("");
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	let change = Change::Add(new_alias("team@example.org", &["alice@example.org"]));
	let code = super::state::commit_state(
		&load(file.path()),
		&change,
		"added",
		super::state::Mode {
			dry_run: true,
			json: false,
		},
		&mut out,
		&mut status,
	)
	.expect("a dry run succeeds");
	assert_eq!(code, std::process::ExitCode::SUCCESS);
	let diff = String::from_utf8(out).unwrap();
	assert!(
		diff.contains("team@example.org"),
		"the diff names the alias: {diff}"
	);
	assert_eq!(std::fs::read_to_string(file.path()).unwrap(), before);
	assert!(!dir.path().join("address-aliases.toml").exists());
}
