//! The operator's names for the folders of a new account, and the one spam
//! folder, through the configuration.

use super::*;
use crate::imap::junk_moves::move_signal_for;
use crate::imap::mailbox;
use crate::imap::special_use::FolderPolicy;

fn policy(extra: &str) -> FolderPolicy {
	let (_dir, config) = super::config(extra);
	FolderPolicy::from_config(&config)
}

fn names(data: &std::path::Path, account: &str) -> Vec<String> {
	mailbox::list(data, account)[1..].to_vec()
}

const ES: &str = r#"
[storage.folders.names]
junk = "Correo no deseado"
trash = "Papelera"
sent = "Enviados"
drafts = "Borradores"
archive = "Archivo"
"#;

#[test]
fn the_default_policy_creates_the_folders_it_always_did() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::ensure_defaults_with(dir.path(), "a@example.org", &FolderPolicy::default())
		.expect("defaults");
	assert_eq!(
		names(dir.path(), "a@example.org"),
		["Archive", "Drafts", "Rejects", "Sent", "Trash"]
	);
	assert_eq!(Roles::load(dir.path(), "a@example.org"), Roles::default());
}

#[test]
fn a_domain_name_set_creates_those_folders_and_records_their_roles() {
	let dir = tempfile::tempdir().expect("tempdir");
	let policy = policy(ES);
	mailbox::ensure_defaults_with(dir.path(), "a@example.org", &policy).expect("defaults");
	assert_eq!(
		names(dir.path(), "a@example.org"),
		[
			"Archivo",
			"Borradores",
			"Correo no deseado",
			"Enviados",
			"Papelera"
		]
	);
	let roles = Roles::load(dir.path(), "a@example.org");
	assert_eq!(roles.recorded(Role::Trash), Some("Papelera"));
	assert_eq!(roles.attribute("Enviados"), "\\Sent");
	assert_eq!(roles.attribute("Correo no deseado"), "\\Junk");
	// A second login changes nothing.
	mailbox::ensure_defaults_with(dir.path(), "a@example.org", &policy).expect("again");
	assert_eq!(names(dir.path(), "a@example.org").len(), 5);
}

#[test]
fn an_account_that_already_has_the_english_folders_gets_no_second_set() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::ensure_defaults(dir.path(), "a@example.org").expect("old defaults");
	mailbox::ensure_defaults_with(dir.path(), "a@example.org", &policy(ES)).expect("new policy");
	assert_eq!(
		names(dir.path(), "a@example.org"),
		["Archive", "Drafts", "Rejects", "Sent", "Trash"]
	);
	assert_eq!(Roles::load(dir.path(), "a@example.org"), Roles::default());
}

#[test]
fn a_domain_beats_its_tenant_and_the_tenant_beats_the_server() {
	let policy = policy(
		r#"
[[tenant]]
name = "acme"
domains = ["other.example"]
[storage.folders.names]
trash = "Papelera"
sent = "Enviados"
[storage.folders.tenants.acme]
trash = "Lixeira"
[storage.folders.domains."other.example"]
sent = "Enviadas"
"#,
	);
	assert_eq!(policy.name_for("a@example.org", Role::Trash), "Papelera");
	assert_eq!(policy.name_for("a@OTHER.example", Role::Trash), "Lixeira");
	assert_eq!(policy.name_for("a@other.example", Role::Sent), "Enviadas");
	assert_eq!(policy.name_for("a@example.org", Role::Drafts), "Drafts");
	assert_eq!(policy.name_for("a@example.org", Role::Junk), "Rejects");
}

#[test]
fn a_name_that_is_not_a_folder_stops_the_start() {
	for bad in ["INBOX", "a/../b", "x\u{0}y", ""] {
		let text = format!("[storage.folders.names]\ntrash = {bad:?}\n");
		let dir = tempfile::tempdir().expect("directory");
		let full = format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{text}",
			dir.path()
		);
		assert!(
			crate::config::Config::parse_text(&full, std::path::Path::new("mail.toml")).is_err(),
			"{bad:?}"
		);
	}
}

#[test]
fn a_domain_or_tenant_the_server_does_not_have_is_refused() {
	for table in [
		"[storage.folders.domains.\"nowhere.example\"]\ntrash = \"X\"\n",
		"[storage.folders.tenants.ghost]\ntrash = \"X\"\n",
	] {
		let dir = tempfile::tempdir().expect("directory");
		let full = format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{table}",
			dir.path()
		);
		assert!(
			crate::config::Config::parse_text(&full, std::path::Path::new("mail.toml")).is_err()
		);
	}
}

#[test]
fn every_spam_filter_name_lands_in_one_folder_when_the_operator_asks() {
	let one = policy("[storage.folders]\nsingle_spam_folder = true\n");
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::ensure_defaults_with(dir.path(), "a@example.org", &one).expect("defaults");
	assert_eq!(
		names(dir.path(), "a@example.org"),
		["Archive", "Drafts", "Junk", "Sent", "Trash"]
	);
	for logical in ["Rejects", "Junk", "rejects"] {
		assert_eq!(
			one.delivery_target(dir.path(), "a@example.org", logical),
			"Junk"
		);
	}
	assert_eq!(
		one.delivery_target(dir.path(), "a@example.org", "Archive"),
		"Archive"
	);
	// By default each filter keeps its own name.
	let two = FolderPolicy::default();
	assert_eq!(
		two.delivery_target(dir.path(), "a@example.org", "Rejects"),
		"Rejects"
	);
	assert_eq!(
		two.delivery_target(dir.path(), "a@example.org", "Junk"),
		"Junk"
	);
}

#[test]
fn a_spam_folder_the_account_chose_receives_every_filter_even_without_the_switch() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::ensure_defaults(dir.path(), "a@example.org").expect("defaults");
	mailbox::create(dir.path(), "a@example.org", "Basura").expect("create");
	set(dir.path(), "a@example.org", Role::Junk, "Basura").expect("set");
	let two = FolderPolicy::default();
	for logical in ["Rejects", "Junk"] {
		assert_eq!(
			two.delivery_target(dir.path(), "a@example.org", logical),
			"Basura"
		);
	}
}

#[test]
fn a_renamed_spam_folder_still_teaches_the_corpus() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::ensure_defaults(dir.path(), "a@example.org").expect("defaults");
	mailbox::create(dir.path(), "a@example.org", "Basura").expect("create");
	set(dir.path(), "a@example.org", Role::Junk, "Basura").expect("set");
	let roles = Roles::load(dir.path(), "a@example.org");
	assert!(move_signal_for(&roles, "INBOX", "Basura", true).is_some());
	assert!(move_signal_for(&roles, "Basura", "INBOX", true).is_some());
	assert!(move_signal_for(&roles, "INBOX", "Rejects", true).is_none());
}
