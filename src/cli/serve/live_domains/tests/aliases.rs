//! An alias written by `epistle alias` or by `POST /api/v1/aliases` reaches
//! the running directory through the file watcher, with no restart: mail to
//! the alias resolves to the account, and a removed alias stops resolving.

use std::sync::Arc;

use super::*;
use crate::aliases::edit::{self, NewAlias};
use crate::aliases::{AliasesFile, Change, Origin};
use crate::smtp::address::Address;

const ACCOUNTS: &str = "[[accounts]]\nname = 'alice'\naddresses = ['alice@example.org']\npassword_hash = '$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000'\n";

fn aliases_loaded(server: &mut Server) -> bool {
	server
		.watcher
		.poll()
		.events
		.contains(&PollEvent::Loaded(PollTarget::State(
			crate::aliases::FILE_NAME,
		)))
}

fn follow_all(server: &Server) {
	follow(
		&server.live,
		Followers {
			account_store: Arc::clone(&server.store),
			signer: None,
			srs: crate::storage::SrsSlot::default(),
		},
	);
}

fn reaches(server: &Server, alias: &str) -> Option<Vec<(String, String)>> {
	let address = Address::parse(alias).unwrap();
	server.store.handle().current().final_recipients(&address)
}

fn add(address: &str, members: &[&str]) -> Change {
	Change::Add(NewAlias {
		address: address.into(),
		members: members.iter().map(|member| member.to_string()).collect(),
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	})
}

#[test]
fn the_start_writes_the_alias_state_file_from_the_configuration_file() {
	let server = server(&format!(
		"{ACCOUNTS}[[alias]]\naddress = 'team@example.org'\nmembers = ['alice@example.org']\n"
	));
	let file = AliasesFile::read(&crate::aliases::path(&server.config.data_dir))
		.unwrap()
		.expect("written at the start");
	assert_eq!(file.aliases.len(), 1);
	assert_eq!(server.live.current().alias.len(), 1);
	assert!(server.live.tracked().contains(&crate::aliases::FILE_NAME));
}

#[test]
fn an_alias_written_to_the_state_file_resolves_without_a_restart_and_stops_when_removed() {
	let mut server = server(ACCOUNTS);
	follow_all(&server);
	assert_eq!(reaches(&server, "team@example.org"), None);
	edit::commit(
		&server.config,
		&add("team@example.org", &["alice@example.org"]),
		&Origin::Api { confined_to: None },
	)
	.unwrap();
	assert_eq!(
		reaches(&server, "team@example.org"),
		None,
		"not before the poll"
	);
	assert!(aliases_loaded(&mut server));
	assert_eq!(
		reaches(&server, "team@example.org"),
		Some(vec![("alice".to_string(), "alice@example.org".to_string())]),
		"the copy goes to the account the member names"
	);
	assert_eq!(server.live.current().alias.len(), 1);
	edit::commit(
		&server.config,
		&Change::Remove {
			address: "TEAM@example.org".into(),
		},
		&Origin::Operator,
	)
	.unwrap();
	assert!(aliases_loaded(&mut server));
	assert_eq!(reaches(&server, "team@example.org"), None);
}

#[test]
fn an_account_added_on_the_alias_address_is_refused_once_the_alias_is_live() {
	let mut server = server(ACCOUNTS);
	follow_all(&server);
	edit::commit(
		&server.config,
		&add("team@example.org", &["alice@example.org"]),
		&Origin::Operator,
	)
	.unwrap();
	assert!(aliases_loaded(&mut server));
	let taken = crate::directory_store::DynamicAccount {
		name: "team".into(),
		addresses: vec!["team@example.org".into()],
		password_hash: "stub".into(),
		..Default::default()
	};
	assert!(
		server.store.add(taken).is_err(),
		"the running store sees the alias the state file holds"
	);
}

#[test]
fn a_state_file_that_does_not_load_leaves_the_running_aliases_as_they_were() {
	let mut server = server(ACCOUNTS);
	follow_all(&server);
	edit::commit(
		&server.config,
		&add("team@example.org", &["alice@example.org"]),
		&Origin::Operator,
	)
	.unwrap();
	assert!(aliases_loaded(&mut server));
	std::fs::write(
		crate::aliases::path(&server.config.data_dir),
		"[[alias]]\naddress = \"x\"\n",
	)
	.unwrap();
	let report = server.watcher.poll();
	assert!(report.events.iter().any(|event| matches!(
		event,
		PollEvent::BadParse(PollTarget::State(name)) if *name == crate::aliases::FILE_NAME
	)));
	assert!(reaches(&server, "team@example.org").is_some());
}
