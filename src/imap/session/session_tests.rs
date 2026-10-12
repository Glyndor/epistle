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
			crate::smtp::auth::tests::hash(fixtures::password()),
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
			crate::smtp::auth::tests::hash(fixtures::password()),
		)])
		.with_scram([("alice".to_string(), stored)]),
	)
}

#[path = "session_tests_acl.rs"]
mod acl;
#[path = "session_tests_auth.rs"]
mod auth;
#[path = "session_tests_auth_ban_lifecycle.rs"]
mod auth_ban_lifecycle;
#[path = "session_tests_auth_bans.rs"]
mod auth_bans;
#[path = "session_tests_basic.rs"]
mod basic;
#[path = "session_tests_commands.rs"]
mod commands_tests;
#[path = "session_tests_encoded_search.rs"]
mod encoded_search;
#[path = "session_tests_keyword_search.rs"]
mod keyword_search;
#[path = "session_tests_metadata.rs"]
mod metadata;
#[path = "session_tests_misc.rs"]
mod misc;
#[path = "session_tests_paths.rs"]
mod paths;
#[path = "session_tests_quota_zero.rs"]
mod quota_zero;
#[path = "session_tests_search.rs"]
mod search;

#[path = "session_tests_rev1.rs"]
mod rev1;

#[path = "session_tests_rev1_recent.rs"]
mod rev1_recent;

#[path = "session_tests_rev1_search.rs"]
mod rev1_search;

#[path = "session_tests_rev1_check.rs"]
mod rev1_check;

#[path = "session_tests_rev1_list.rs"]
mod rev1_list;

#[path = "session_tests_rev1_flow.rs"]
mod rev1_flow;

#[path = "session_tests_rfc9051_select.rs"]
mod rfc9051_select;

#[path = "session_tests_rfc5182_searchres.rs"]
mod rfc5182_searchres;

#[path = "session_tests_rfc9051_uid_star.rs"]
mod rfc9051_uid_star;

#[path = "session_tests_rfc9051_poll.rs"]
mod rfc9051_poll;

#[cfg(test)]
#[path = "session_tests_default_mailboxes.rs"]
mod default_mailboxes;

#[path = "session_tests_fetch_envelope.rs"]
mod fetch_envelope;

#[path = "session_tests_fetch_structure.rs"]
mod fetch_structure;

#[path = "session_tests_fetch_sections.rs"]
mod fetch_sections;

#[path = "session_tests_fetch_aliases.rs"]
mod fetch_aliases;

#[path = "session_tests_fetch_edges.rs"]
mod fetch_edges;

#[path = "session_tests_fetch_depth.rs"]
mod fetch_depth;

#[path = "session_tests_capabilities.rs"]
mod capabilities;

#[path = "session_tests_utf8.rs"]
mod utf8;

#[path = "session_tests_quota_names.rs"]
mod quota_names;

#[path = "session_tests_utf8_responses.rs"]
mod utf8_responses;

#[path = "session_tests_flags_update.rs"]
mod flags_update;
