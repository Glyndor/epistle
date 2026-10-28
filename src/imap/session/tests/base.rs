use super::helpers::format_internaldate;
use super::*;
use crate::test_fixtures as fixtures;
use std::collections::HashMap;
use std::sync::Arc;

use crate::smtp::directory::Directory;

pub fn directory() -> Arc<Directory> {
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixtures::password()),
		)])),
	)
}

pub fn deliver(dir: &std::path::Path, body: &[u8]) {
	let new_dir = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	let id = uuid::Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
}

pub fn logged_in(dir: &std::path::Path) -> Session {
	let mut session = Session::new("mail.example.org", dir.to_path_buf(), directory());
	let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert!(text(&output).contains("a1 OK"), "{}", text(&output));
	session
}

pub fn text(output: &Output) -> String {
	String::from_utf8_lossy(&output.bytes).to_string()
}

/// A directory whose `alice` account has SCRAM-SHA-256 credentials.
pub fn scram_directory() -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored = ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		fixtures::salt(),
		4096,
	));
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixtures::password()),
		)])
		.with_scram([("alice".to_string(), stored)]),
	)
}

mod acl;
mod auth;
mod auth_ban_lifecycle;
mod auth_ban_owner_known_network;
mod auth_ban_toctou;
mod auth_bans;
mod basic;
mod commands_tests;
mod condstore_search;
mod encoded_search;
mod esearch_sets;
mod gate_busy;
mod keyword_search;
mod learn_e2e;
mod learn_moves;
mod login_gate;
mod metadata;
mod misc;
mod oauth_flow;
mod paths;
mod quota_zero;
mod scram_decoy;
mod search;
mod search_headers;
mod search_keys;

mod rev1;

mod rev1_recent;

mod rev1_search;

mod rev1_check;

mod rev1_list;

mod rev1_flow;

mod rfc9051_select;

mod rfc5182_searchres;

mod rfc9051_uid_star;

mod rfc9051_poll;

#[cfg(test)]
mod default_mailboxes;

mod fetch_envelope;

mod fetch_structure;

mod fetch_sections;

mod fetch_aliases;

mod fetch_edges;

mod fetch_depth;

mod capabilities;

mod utf8;

mod quota_names;

mod hierarchy_surfaces;

mod utf8_responses;

mod flags_update;

mod save_sent;

mod append_exists;

mod noop_exists;

mod cross_session;

mod sort_dates;

mod sort_text;

mod thread_ordered;

mod thread_references;

mod appendlimit;

mod per_account;

mod notify_status;

mod uidvalidity;

mod fetch_whole;

mod append_binary;

mod append_date;
