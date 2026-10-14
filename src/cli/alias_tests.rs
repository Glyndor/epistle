//! `epistle alias`: list/show/add/remove flow on a fixture config.

use std::io::Write;
use std::path::Path;

use super::alias_writers::commit_and_restart;
use super::*;
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

#[test]
fn add_writes_a_new_alias_with_optional_fields() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = AddArgs {
		address: "team@example.org".to_string(),
		members: vec![
			"alice@example.org".to_string(),
			"bob@example.org".to_string(),
		],
		senders: vec!["ceo@example.org".to_string()],
		list_id: Some("team.example.org".to_string()),
		visible: true,
	};
	let _ = config;
	add_alias(&load(file.path()), &mut document, &args).expect("add must succeed");
	commit_and_restart(
		document,
		&args.address,
		"added",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		after.contains("team@example.org"),
		"file must contain the alias"
	);
	assert!(after.contains("alice@example.org"));
	assert!(after.contains("ceo@example.org"));
	assert!(after.contains("team.example.org"));
	assert!(after.contains("hidden = false"));
}

#[test]
fn add_refuses_a_duplicate_alias() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = AddArgs {
		address: "team@example.org".to_string(),
		members: vec!["bob@example.org".to_string()],
		senders: Vec::new(),
		list_id: None,
		visible: false,
	};
	let err = add_alias(&config, &mut document, &args).unwrap_err();
	assert!(err.contains("already exists"), "unexpected message: {err}");
}

#[test]
fn add_refuses_an_alias_address_outside_configured_domains() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = AddArgs {
		address: "team@other.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		list_id: None,
		visible: false,
	};
	let err = add_alias(&config, &mut document, &args).unwrap_err();
	assert_eq!(
		err,
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
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = AddArgs {
		address: "alice@example.org".to_string(),
		members: vec!["bob@example.org".to_string()],
		senders: Vec::new(),
		list_id: None,
		visible: false,
	};
	let err = add_alias(&config, &mut document, &args).unwrap_err();
	assert!(
		err.contains("already used by an account"),
		"unexpected message: {err}"
	);
}

#[test]
fn add_refuses_an_address_used_by_another_alias() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = AddArgs {
		address: "team@example.org".to_string(),
		members: vec!["bob@example.org".to_string()],
		senders: Vec::new(),
		list_id: None,
		visible: false,
	};
	let err = add_alias(&config, &mut document, &args).unwrap_err();
	assert!(err.contains("already exists"), "unexpected message: {err}");
}

#[test]
fn remove_drops_an_existing_alias() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n\n[[alias]]\naddress = \"ops@example.org\"\nmembers = [\"alice@example.org\"]\n",
	);
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	remove_alias(&config, &mut document, "team@example.org").expect("remove must succeed");
	commit_and_restart(
		document,
		"team@example.org",
		"removed",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(!after.contains("team@example.org"));
	assert!(after.contains("ops@example.org"));
}

#[test]
fn remove_refuses_an_unknown_alias() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = remove_alias(&config, &mut document, "team@example.org").unwrap_err();
	assert!(err.contains("not found"), "unexpected message: {err}");
}

#[test]
fn member_add_appends_to_the_alias_members_list() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = MemberArgs {
		action: MemberSubcommand::Add {
			address: "team@example.org".to_string(),
			member: "bob@example.org".to_string(),
		},
	};
	member_edit(&config, &mut document, args).expect("add member must succeed");
	commit_and_restart(
		document,
		"team@example.org",
		"member added",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let config = load(file.path());
	let alias = &config.alias[0];
	assert_eq!(
		alias.members,
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
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = MemberArgs {
		action: MemberSubcommand::Remove {
			address: "team@example.org".to_string(),
			member: "bob@example.org".to_string(),
		},
	};
	member_edit(&config, &mut document, args).expect("remove member must succeed");
	commit_and_restart(
		document,
		"team@example.org",
		"member removed",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let config = load(file.path());
	let alias = &config.alias[0];
	assert_eq!(alias.members, vec!["alice@example.org".to_string()]);
}

#[test]
fn member_remove_refuses_to_leave_an_alias_empty() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = MemberArgs {
		action: MemberSubcommand::Remove {
			address: "team@example.org".to_string(),
			member: "alice@example.org".to_string(),
		},
	};
	let err = member_edit(&config, &mut document, args).unwrap_err();
	assert!(err.contains("no members"), "unexpected message: {err}");
}

#[test]
fn sender_add_and_remove_round_trip() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = SenderArgs {
		action: SenderSubcommand::Add {
			address: "team@example.org".to_string(),
			sender: "ceo@example.org".to_string(),
		},
	};
	sender_edit(&config, &mut document, args).expect("add sender must succeed");
	commit_and_restart(
		document,
		"team@example.org",
		"sender added",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let config = load(file.path());
	assert_eq!(config.alias[0].senders, vec!["ceo@example.org".to_string()]);

	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let args = SenderArgs {
		action: SenderSubcommand::Remove {
			address: "team@example.org".to_string(),
			sender: "ceo@example.org".to_string(),
		},
	};
	sender_edit(&config, &mut document, args).expect("remove sender must succeed");
	commit_and_restart(
		document,
		"team@example.org",
		"sender removed",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	let config = load(file.path());
	assert!(config.alias[0].senders.is_empty());
}

#[test]
fn add_alias_address_validates_against_the_store() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let store = open_store(&config).expect("store must open");
	assert!(validate_alias_address(&config, "alice@example.org", &store).is_ok());
	assert_eq!(
		validate_alias_address(&config, "team@other.org", &store).unwrap_err(),
		"alias address: other.org is not a domain this server handles",
		"address outside configured domains must be refused"
	);
	assert_eq!(
		validate_alias_address(&config, "not-an-email", &store).unwrap_err(),
		"alias address: not-an-email has no @",
		"a malformed address must be refused"
	);
}

#[test]
fn invalid_member_or_sender_address_is_refused() {
	assert!(validate_member_or_sender("member", "alice@example.org").is_ok());
	assert_eq!(
		validate_member_or_sender("member", "bad").unwrap_err(),
		"member address: bad has no @"
	);
}

#[test]
fn dry_run_prints_a_diff_and_does_not_write() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out: Vec<u8> = Vec::new();
	let status: Vec<u8> = Vec::new();
	let args = AddArgs {
		address: "team@example.org".to_string(),
		members: vec!["alice@example.org".to_string()],
		senders: Vec::new(),
		list_id: None,
		visible: false,
	};
	let _ = args;
	let _ = config;
	// Re-implement the dry-run commit because the helper hard-codes the
	// restart closure.
	let mut members = toml_edit::Array::new();
	members.push(toml_edit::Value::from("alice@example.org".to_string()));
	document
		.upsert_element(
			"alias",
			"address",
			"team@example.org",
			&[
				(
					"address",
					toml_edit::Value::from("team@example.org".to_string()),
				),
				("members", toml_edit::Value::Array(members)),
			],
		)
		.unwrap();
	let rendered = document.dry_run().unwrap();
	let _ = write!(out, "{rendered}");
	assert!(!out.is_empty(), "dry-run must emit the diff");
	assert_eq!(
		std::fs::read_to_string(file.path()).unwrap(),
		before,
		"dry-run must leave the file untouched"
	);
	let _ = status;
}
