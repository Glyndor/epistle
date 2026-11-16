use super::*;
use crate::imap::mailbox;

fn account() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = dir.path().to_path_buf();
	mailbox::ensure_defaults(&data, "alice@example.org").expect("defaults");
	(dir, data)
}

const ACCOUNT: &str = "alice@example.org";

#[test]
fn an_account_with_no_file_keeps_the_name_table() {
	let (_dir, data) = account();
	let roles = Roles::load(&data, ACCOUNT);
	for (name, attribute) in [
		("Junk", "\\Junk"),
		("Rejects", "\\Junk"),
		("Sent", "\\Sent"),
		("Trash", "\\Trash"),
		("Drafts", "\\Drafts"),
		("Archive", "\\Archive"),
		("INBOX", ""),
		("Projects", ""),
	] {
		assert_eq!(roles.attribute(name), attribute, "{name}");
		assert_eq!(
			roles.attribute(name),
			crate::imap::special_use::attribute(name)
		);
	}
}

#[test]
fn a_recorded_role_belongs_to_its_folder_and_takes_the_name_table_with_it() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Correo no deseado").expect("create");
	set(&data, ACCOUNT, Role::Junk, "Correo no deseado").expect("set");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.attribute("Correo no deseado"), "\\Junk");
	assert!(roles.is_junk("Correo no deseado"));
	// The spam folder is the account's choice now: the English names are
	// ordinary folders, and moving mail out of them teaches nothing.
	assert_eq!(roles.attribute("Rejects"), "");
	assert_eq!(roles.attribute("Junk"), "");
	assert!(!roles.is_junk("Rejects"));
	// The other roles are untouched.
	assert_eq!(roles.attribute("Sent"), "\\Sent");
}

#[test]
fn a_role_needs_an_existing_folder_and_a_folder_holds_one_role() {
	let (_dir, data) = account();
	assert!(set(&data, ACCOUNT, Role::Sent, "Nowhere").is_err());
	assert!(set(&data, ACCOUNT, Role::Sent, "INBOX").is_err());
	mailbox::create(&data, ACCOUNT, "Mine").expect("create");
	set(&data, ACCOUNT, Role::Sent, "Mine").expect("sent");
	set(&data, ACCOUNT, Role::Archive, "Mine").expect("archive");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.recorded(Role::Archive), Some("Mine"));
	assert_eq!(roles.recorded(Role::Sent), None);
	assert_eq!(roles.attribute("Mine"), "\\Archive");
	// `Sent` has no record again, so the name table answers for it.
	assert_eq!(roles.attribute("Sent"), "\\Sent");
}

#[test]
fn clearing_a_role_gives_the_name_table_back() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Mine").expect("create");
	set(&data, ACCOUNT, Role::Trash, "Mine").expect("set");
	assert_eq!(Roles::load(&data, ACCOUNT).attribute("Trash"), "");
	clear(&data, ACCOUNT, Role::Trash).expect("clear");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.attribute("Trash"), "\\Trash");
	assert_eq!(roles.attribute("Mine"), "");
	assert!(
		!data.join("accounts/alice@example.org/.roles").exists(),
		"an account with no role keeps no file"
	);
}

#[test]
fn a_malformed_file_records_nothing() {
	let (_dir, data) = account();
	std::fs::write(
		data.join("accounts/alice@example.org/.roles"),
		"nonsense\njunk\t\ntrash\tINBOX\nfoo\tBar\n",
	)
	.expect("write");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles, Roles::default());
	assert_eq!(roles.attribute("Rejects"), "\\Junk");
}

#[test]
fn a_hostile_account_name_reads_nothing_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(Roles::load(dir.path(), "../x"), Roles::default());
	assert!(set(dir.path(), "../x", Role::Junk, "Junk").is_err());
}
