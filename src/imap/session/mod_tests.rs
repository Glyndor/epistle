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

#[path = "mod_tests_acl.rs"]
mod acl;
#[path = "mod_tests_auth.rs"]
mod auth;
#[path = "mod_tests_auth_ban_lifecycle.rs"]
mod auth_ban_lifecycle;
#[path = "mod_tests_auth_ban_owner_known_network.rs"]
mod auth_ban_owner_known_network;
#[path = "mod_tests_auth_ban_toctou.rs"]
mod auth_ban_toctou;
#[path = "mod_tests_auth_bans.rs"]
mod auth_bans;
#[path = "mod_tests_basic.rs"]
mod basic;
#[path = "mod_tests_commands.rs"]
mod commands_tests;
#[path = "mod_tests_condstore_search.rs"]
mod condstore_search;
#[path = "mod_tests_encoded_search.rs"]
mod encoded_search;
#[path = "mod_tests_esearch_sets.rs"]
mod esearch_sets;
#[path = "mod_tests_gate_busy.rs"]
mod gate_busy;
#[path = "mod_tests_keyword_search.rs"]
mod keyword_search;
#[path = "mod_tests_learn_e2e.rs"]
mod learn_e2e;
#[path = "mod_tests_learn_moves.rs"]
mod learn_moves;
#[path = "mod_tests_login_gate.rs"]
mod login_gate;
#[path = "mod_tests_metadata.rs"]
mod metadata;
#[path = "mod_tests_misc.rs"]
mod misc;
#[path = "mod_tests_oauth_flow.rs"]
mod oauth_flow;
#[path = "mod_tests_paths.rs"]
mod paths;
#[path = "mod_tests_quota_zero.rs"]
mod quota_zero;
#[path = "mod_tests_scram_decoy.rs"]
mod scram_decoy;
#[path = "mod_tests_search.rs"]
mod search;
#[path = "mod_tests_search_headers.rs"]
mod search_headers;
#[path = "mod_tests_search_keys.rs"]
mod search_keys;

#[path = "mod_tests_rev1.rs"]
mod rev1;

#[path = "mod_tests_rev1_recent.rs"]
mod rev1_recent;

#[path = "mod_tests_rev1_search.rs"]
mod rev1_search;

#[path = "mod_tests_rev1_check.rs"]
mod rev1_check;

#[path = "mod_tests_rev1_list.rs"]
mod rev1_list;

#[path = "mod_tests_rev1_flow.rs"]
mod rev1_flow;

#[path = "mod_tests_rfc9051_select.rs"]
mod rfc9051_select;

#[path = "mod_tests_rfc5182_searchres.rs"]
mod rfc5182_searchres;

#[path = "mod_tests_rfc9051_uid_star.rs"]
mod rfc9051_uid_star;

#[path = "mod_tests_rfc9051_poll.rs"]
mod rfc9051_poll;

#[cfg(test)]
#[path = "mod_tests_default_mailboxes.rs"]
mod default_mailboxes;

#[path = "mod_tests_fetch_envelope.rs"]
mod fetch_envelope;

#[path = "mod_tests_fetch_structure.rs"]
mod fetch_structure;

#[path = "mod_tests_fetch_sections.rs"]
mod fetch_sections;

#[path = "mod_tests_fetch_aliases.rs"]
mod fetch_aliases;

#[path = "mod_tests_fetch_edges.rs"]
mod fetch_edges;

#[path = "mod_tests_fetch_depth.rs"]
mod fetch_depth;

#[path = "mod_tests_capabilities.rs"]
mod capabilities;

#[path = "mod_tests_utf8.rs"]
mod utf8;

#[path = "mod_tests_quota_names.rs"]
mod quota_names;

#[path = "mod_tests_hierarchy_surfaces.rs"]
mod hierarchy_surfaces;

#[path = "mod_tests_utf8_responses.rs"]
mod utf8_responses;

#[path = "mod_tests_flags_update.rs"]
mod flags_update;

#[path = "mod_tests_save_sent.rs"]
mod save_sent;

#[path = "mod_tests_append_exists.rs"]
mod append_exists;

#[path = "mod_tests_noop_exists.rs"]
mod noop_exists;

#[path = "mod_tests_cross_session.rs"]
mod cross_session;

#[path = "mod_tests_sort_dates.rs"]
mod sort_dates;

#[path = "mod_tests_sort_text.rs"]
mod sort_text;

#[path = "mod_tests_thread_ordered.rs"]
mod thread_ordered;

#[path = "mod_tests_thread_references.rs"]
mod thread_references;

#[path = "mod_tests_appendlimit.rs"]
mod appendlimit;

#[path = "mod_tests_per_account.rs"]
mod per_account;

#[path = "mod_tests_notify_status.rs"]
mod notify_status;

#[path = "mod_tests_uidvalidity.rs"]
mod uidvalidity;

#[path = "mod_tests_fetch_whole.rs"]
mod fetch_whole;

#[path = "mod_tests_append_binary.rs"]
mod append_binary;

#[path = "mod_tests_append_date.rs"]
mod append_date;
