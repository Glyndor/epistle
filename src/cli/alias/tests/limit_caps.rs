//! The caps on aliases, lists and members: each scope, tightening, and two
//! commands racing for the last place.

use std::io::Write;

use super::super::caps::{check_add, check_member_add};
use super::writers::commit_and_restart;
use super::*;
use crate::cli::config_edit::ConfigDocument;

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

fn args(address: &str, members: &[&str], list: bool) -> AddArgs {
	AddArgs {
		address: address.to_string(),
		members: members.iter().map(|m| m.to_string()).collect(),
		senders: Vec::new(),
		list_id: list.then(|| "team.example.org".to_string()),
		visible: false,
	}
}

const ONE: &str = "[[alias]]\naddress = \"one@example.org\"\nmembers = [\"a@example.org\"]\n";

#[test]
fn the_server_cap_on_aliases_counts_per_domain() {
	let (_dir, file) = fixture(&format!("[limits]\nmax_aliases_per_domain = 1\n{ONE}"));
	let document = ConfigDocument::open(file.path()).unwrap();
	let refusal = check_add(
		&document,
		&args("two@example.org", &["b@example.org"], false),
	)
	.expect_err("the domain is full");
	for part in [
		"domain example.org",
		"1 aliases per domain",
		"the server",
		"remove one",
	] {
		assert!(refusal.contains(part), "{refusal:?} lacks {part:?}");
	}
	check_add(
		&document,
		&args("two@example.net", &["b@example.net"], false),
	)
	.expect("another domain has its own room");
}

#[test]
fn a_domain_scope_tightens_the_server_and_lists_have_their_own_cap() {
	let (_dir, file) = fixture(
		"[limits]\nmax_lists_per_domain = 5\n\
		 [[limit_scope]]\ndomain = \"example.net\"\nmax_lists_per_domain = 0\nmax_members_per_list = 1\n",
	);
	let document = ConfigDocument::open(file.path()).unwrap();
	check_add(&document, &args("l@example.org", &["a@example.org"], true)).expect("org has room");
	let refusal = check_add(&document, &args("l@example.net", &["a@example.net"], true))
		.expect_err("net allows no list");
	assert!(refusal.contains("mailing lists per domain") && refusal.contains("domain example.net"));
	check_add(&document, &args("a@example.net", &["a@example.net"], false))
		.expect("a plain alias is not a list");
	let refusal = check_add(
		&document,
		&args("p@example.net", &["a@example.net", "b@example.net"], false),
	)
	.expect_err("one member at most");
	assert!(refusal.contains("members per alias or list"));
}

#[test]
fn members_are_capped_on_add_and_on_member_add() {
	let (_dir, file) = fixture(&format!("[limits]\nmax_members_per_list = 1\n{ONE}"));
	let document = ConfigDocument::open(file.path()).unwrap();
	let refusal = check_member_add(&document, "one@example.org").expect_err("full");
	assert!(refusal.contains("alias one@example.org") && refusal.contains("remove a member"));
	assert!(check_member_add(&document, "missing@example.org").is_ok());
}

#[test]
fn nothing_configured_caps_nothing() {
	let (_dir, file) = fixture(ONE);
	let document = ConfigDocument::open(file.path()).unwrap();
	check_add(
		&document,
		&args("x@example.org", &["a@example.org", "b@example.org"], true),
	)
	.expect("unlimited by default");
	check_member_add(&document, "one@example.org").expect("unlimited by default");
}

#[test]
fn two_commands_racing_for_the_last_place_admit_one() {
	let (_dir, file) = fixture("[limits]\nmax_aliases_per_domain = 1\n");
	// Both commands read the file before either writes it, and both pass.
	let mut first = ConfigDocument::open(file.path()).unwrap();
	let mut second = ConfigDocument::open(file.path()).unwrap();
	let one = args("one@example.org", &["a@example.org"], false);
	let two = args("two@example.org", &["b@example.org"], false);
	check_add(&first, &one).expect("room for the first");
	check_add(&second, &two).expect("room for the second, as far as it can see");
	let config = load_config(file.path());
	add_alias(&config, &mut first, &one).expect("edit");
	add_alias(&config, &mut second, &two).expect("edit");
	let landed = commit_and_restart(
		first,
		&one.address,
		"added",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("the first commit lands");
	assert_eq!(landed, std::process::ExitCode::SUCCESS);
	let lost = commit_and_restart(
		second,
		&two.address,
		"added",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	);
	assert!(
		lost.is_err(),
		"the second finds the file changed and writes nothing"
	);
	let text = std::fs::read_to_string(file.path()).unwrap();
	assert!(text.contains("one@example.org") && !text.contains("two@example.org"));
}

fn load_config(path: &std::path::Path) -> crate::config::Config {
	crate::config::Config::load(path).expect("config loads")
}
