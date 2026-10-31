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
mod flags_update;

#[cfg(test)]
mod append;

#[cfg(test)]
mod authentication;

#[cfg(test)]
mod fetch;

#[cfg(test)]
mod searching;

#[cfg(test)]
mod imap4rev1;

#[cfg(test)]
mod session;

#[cfg(test)]
mod thread_order;
