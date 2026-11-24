//! The caps on aliases, lists and members: each scope, tightening, and two
//! commands racing for the last place.

use std::io::Write;

use crate::aliases::edit::NewAlias;
use crate::aliases::{AliasError, Change, Origin, edit};

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n\
		 domains = [\"example.org\", \"example.net\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn add(address: &str, members: &[&str], list: bool) -> Change {
	Change::Add(NewAlias {
		address: address.to_string(),
		members: members.iter().map(|m| m.to_string()).collect(),
		senders: Vec::new(),
		list_id: list.then(|| "team.example.org".to_string()),
		hidden: true,
	})
}

fn commit(path: &std::path::Path, change: &Change) -> Result<edit::Committed, AliasError> {
	edit::commit(&load_config(path), change, &Origin::Operator)
}

const ONE: &str = "[[alias]]\naddress = \"one@example.org\"\nmembers = [\"a@example.org\"]\n";

fn cap_text(result: Result<edit::Committed, AliasError>) -> String {
	match result.expect_err("refused") {
		AliasError::Capped(reached) => reached.to_string(),
		other => panic!("not a cap: {other}"),
	}
}

#[test]
fn the_server_cap_on_aliases_counts_per_domain() {
	let (_dir, file) = fixture(&format!("[limits]\nmax_aliases_per_domain = 1\n{ONE}"));
	let refusal = cap_text(commit(
		file.path(),
		&add("two@example.org", &["b@example.org"], false),
	));
	for part in [
		"domain example.org",
		"1 aliases per domain",
		"the server",
		"remove one",
	] {
		assert!(refusal.contains(part), "{refusal:?} lacks {part:?}");
	}
	commit(
		file.path(),
		&add("two@example.net", &["b@example.net"], false),
	)
	.expect("another domain has its own room");
}

#[test]
fn a_domain_scope_tightens_the_server_and_lists_have_their_own_cap() {
	let (_dir, file) = fixture(
		"[limits]\nmax_lists_per_domain = 5\n\
		 [[limit_scope]]\ndomain = \"example.net\"\nmax_lists_per_domain = 0\nmax_members_per_list = 1\n",
	);
	edit::preview(
		&load_config(file.path()),
		&add("l@example.org", &["a@example.org"], true),
		&Origin::Operator,
	)
	.expect("org has room");
	let refusal = cap_text(commit(
		file.path(),
		&add("l@example.net", &["a@example.net"], true),
	));
	assert!(refusal.contains("mailing lists per domain") && refusal.contains("domain example.net"));
	commit(
		file.path(),
		&add("a@example.net", &["a@example.net"], false),
	)
	.expect("a plain alias is not a list");
	let refusal = cap_text(commit(
		file.path(),
		&add("p@example.net", &["a@example.net", "b@example.net"], false),
	));
	assert!(refusal.contains("members per alias or list"));
}

#[test]
fn members_are_capped_on_add_and_on_member_add() {
	let (_dir, file) = fixture(&format!("[limits]\nmax_members_per_list = 1\n{ONE}"));
	let refusal = cap_text(commit(
		file.path(),
		&Change::MemberAdd {
			address: "one@example.org".to_string(),
			member: "b@example.org".to_string(),
		},
	));
	assert!(refusal.contains("alias one@example.org") && refusal.contains("remove a member"));
}

#[test]
fn nothing_configured_caps_nothing() {
	let (_dir, file) = fixture(ONE);
	commit(
		file.path(),
		&add("x@example.org", &["a@example.org", "b@example.org"], true),
	)
	.expect("unlimited by default");
	commit(
		file.path(),
		&Change::MemberAdd {
			address: "one@example.org".to_string(),
			member: "c@example.org".to_string(),
		},
	)
	.expect("unlimited by default");
}

#[test]
fn two_commands_racing_for_the_last_place_admit_one() {
	let (_dir, file) = fixture("[limits]\nmax_aliases_per_domain = 1\n");
	let path = file.path().to_path_buf();
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let run = |address: &'static str, member: &'static str| {
		let (path, barrier) = (path.clone(), std::sync::Arc::clone(&barrier));
		std::thread::spawn(move || {
			let config = load_config(&path);
			barrier.wait();
			edit::commit(&config, &add(address, &[member], false), &Origin::Operator)
		})
	};
	let first = run("one@example.org", "a@example.org");
	let second = run("two@example.org", "b@example.org");
	let results = [first.join().unwrap(), second.join().unwrap()];
	assert_eq!(
		results.iter().filter(|result| result.is_ok()).count(),
		1,
		"exactly one of the two takes the last place: {results:?}"
	);
	assert_eq!(load_config(file.path()).alias.len(), 1);
}

fn load_config(path: &std::path::Path) -> crate::config::Config {
	crate::config::Config::load(path).expect("config loads")
}
