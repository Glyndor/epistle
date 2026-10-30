use super::*;

/// A canonical, empty data directory that lives as long as the guard.
fn data_dir() -> (tempfile::TempDir, PathBuf) {
	let guard = tempfile::tempdir().expect("tempdir");
	let dir = guard.path().canonicalize().expect("canonical tempdir");
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	(guard, data)
}

const DANGEROUS: &[&str] = &[
	"",
	".",
	"..",
	"../x",
	"x/..",
	"a/b",
	"a\\b",
	"\\x",
	"/etc/passwd",
	"/",
	"x\0y",
	"x\ny",
	"x\ry",
	"x\ty",
	"x\u{7f}y",
	"x\u{85}y",
];

#[test]
fn plain_component_rejects_dangerous_names() {
	for name in DANGEROUS {
		assert!(
			!is_plain_component(name),
			"{name:?} must not be a plain component"
		);
	}
	let long = "a".repeat(MAX_COMPONENT_LEN + 1);
	assert!(!is_plain_component(&long), "an over-long name is refused");
}

#[test]
fn plain_component_accepts_ordinary_names() {
	for name in ["alice", "Work", "Sent Items", "a.b", "caf\u{e9}", "x-1_y"] {
		assert!(is_plain_component(name), "{name:?} must be accepted");
	}
}

#[test]
fn plain_component_keeps_names_with_dot_dot_inside() {
	for name in ["a..b", "..a", "a..", "Projects..2024"] {
		assert!(is_plain_component(name), "{name:?} is an ordinary name");
	}
}

#[test]
fn account_name_rejects_dangerous_names() {
	for name in DANGEROUS {
		assert_eq!(
			AccountName::new(name),
			Err(InvalidComponent),
			"account {name:?} must be refused"
		);
	}
	let long = "a".repeat(MAX_COMPONENT_LEN + 1);
	assert_eq!(AccountName::new(&long), Err(InvalidComponent));
}

#[test]
fn account_name_accepts_what_accounts_use() {
	for name in ["alice", "bob-2", "a", "0day"] {
		let account = AccountName::new(name).expect("valid account");
		assert_eq!(account.as_str(), name);
	}
	let max = "a".repeat(MAX_COMPONENT_LEN);
	assert!(AccountName::new(&max).is_ok());
}

#[test]
fn account_root_joins_under_accounts() {
	let (_guard, data) = data_dir();
	let account = AccountName::new("alice").expect("account");
	let root = account.root(&data).expect("root");
	assert_eq!(root.as_path(), data.join("accounts/alice"));
	assert_eq!(
		root.child(FixedDir::Archive).expect("archive"),
		data.join("accounts/alice/.archive")
	);
	assert_eq!(
		root.child(FixedDir::Tmp).expect("tmp"),
		data.join("accounts/alice/tmp")
	);
}

#[test]
fn mailbox_name_rejects_dangerous_names() {
	// `a/b` is a hierarchical name, valid for a mailbox but not for an account.
	for name in DANGEROUS.iter().filter(|name| **name != "a/b") {
		assert_eq!(
			MailboxName::new(name),
			Err(InvalidComponent),
			"mailbox {name:?} must be refused"
		);
		assert_eq!(MailboxName::folder(name), Err(InvalidComponent));
	}
	for name in [
		".hidden",
		"trail ",
		"a:b",
		"a*b",
		"caf\u{e9}",
		"Archive/.2024",
	] {
		assert_eq!(
			MailboxName::new(name),
			Err(InvalidComponent),
			"mailbox {name:?} is outside the folder alphabet"
		);
	}
	let long = "a".repeat(MAX_COMPONENT_LEN + 1);
	assert_eq!(MailboxName::new(&long), Err(InvalidComponent));
}

#[test]
fn mailbox_name_accepts_what_folders_use() {
	for name in [
		"Work",
		"Sent Items",
		"a-b_c.d",
		"2024",
		"a..b",
		"Projects..2024",
	] {
		assert_eq!(MailboxName::new(name), Ok(MailboxName::Folder(name)));
	}
	for name in ["INBOX", "inbox", "InBoX"] {
		assert_eq!(MailboxName::new(name), Ok(MailboxName::Inbox));
		assert_eq!(
			MailboxName::folder(name),
			Err(InvalidComponent),
			"INBOX is not a folder"
		);
	}
}

#[test]
fn mailbox_dirs_keep_the_on_disk_layout() {
	let (_guard, data) = data_dir();
	let account = AccountName::new("alice").expect("account");
	let inbox = MailboxName::new("INBOX").expect("inbox");
	assert_eq!(
		inbox.messages_dir(&account, &data).expect("inbox dir"),
		data.join("accounts/alice/new")
	);
	assert_eq!(inbox.folder_dir(&account, &data).expect("inbox"), None);
	let work = MailboxName::new("Work").expect("folder");
	assert_eq!(
		work.messages_dir(&account, &data).expect("messages dir"),
		data.join("accounts/alice/folders/Work/new")
	);
	assert_eq!(
		work.folder_dir(&account, &data).expect("folder dir"),
		Some(data.join("accounts/alice/folders/Work"))
	);
	assert_eq!(
		folders_dir(&account, &data).expect("folders dir"),
		data.join("accounts/alice/folders")
	);
}

#[test]
fn digest_name_is_lowercase_hex_only() {
	let name = DigestName::of("../../etc/passwd").to_string();
	assert_eq!(name.len(), 64, "a SHA-256 digest is 64 hex characters");
	assert!(
		name.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
		"digest names carry hex only: {name}"
	);
	assert_eq!(
		DigestName::of("Alice@Example.ORG"),
		DigestName::of("alice@example.org"),
		"lookups are case-insensitive"
	);
	assert_eq!(
		DigestName::of("abc").to_string(),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	);
}

#[test]
fn digest_name_joins_stay_one_level_deep() {
	let digest = DigestName::of("anything/../at all");
	let (_guard, dir) = data_dir();
	let path = digest.in_dir(&dir).expect("digest path");
	assert_eq!(path.parent(), Some(dir.as_path()));
	let lock = digest.lock_in_dir(&dir).expect("lock path");
	assert_eq!(lock.parent(), Some(dir.as_path()));
	assert!(lock.to_string_lossy().ends_with(".lock"));
}

#[test]
fn message_and_state_files_have_fixed_names() {
	let (_guard, dir) = data_dir();
	let dir = dir.as_path();
	let id = Uuid::parse_str("0190a6f0-0000-7000-8000-000000000001").expect("uuid");
	let cases = [
		(MessageExt::Eml, ".eml"),
		(MessageExt::Flags, ".flags"),
		(MessageExt::Uid, ".uid"),
		(MessageExt::Modseq, ".modseq"),
		(MessageExt::Deleted, ".deleted"),
		(MessageExt::Json, ".json"),
	];
	for (ext, suffix) in cases {
		assert_eq!(
			message_file(dir, id, ext).expect("message file"),
			dir.join(format!("{id}{suffix}"))
		);
		assert_eq!(
			message_tmp_file(dir, id, ext).expect("tmp file"),
			dir.join(format!("{id}{suffix}.tmp"))
		);
	}
	let states = [
		(StateFile::UidNext, ".uidnext"),
		(StateFile::UidValidity, ".uidvalidity"),
		(StateFile::ModseqCounter, ".modseqctr"),
		(StateFile::Vanished, ".vanished"),
		(StateFile::Index, ".index"),
	];
	for (file, name) in states {
		assert_eq!(state_file(dir, file).expect("state file"), dir.join(name));
		assert_eq!(
			state_tmp_file(dir, file).expect("state tmp file"),
			dir.join(format!("{name}.tmp"))
		);
	}
}

#[test]
fn invalid_component_converts_to_invalid_input() {
	let error: std::io::Error = InvalidComponent.into();
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(error.to_string(), "invalid path component");
}

fn assert_outside_root<T: std::fmt::Debug>(result: std::io::Result<T>, what: &str) {
	let error = result.expect_err(what);
	assert_eq!(
		error.kind(),
		std::io::ErrorKind::InvalidInput,
		"{what}: {error}"
	);
}

#[test]
fn account_root_is_refused_when_the_validator_let_a_traversal_through() {
	let (_guard, data) = data_dir();
	std::fs::create_dir_all(data.join("accounts/alice")).expect("tree");
	for name in ["../../outside", "alice/../../../outside", "../alice"] {
		assert_outside_root(
			AccountName::unchecked(name).root(&data),
			&format!("account {name:?}"),
		);
	}
}

#[test]
fn mailbox_dirs_are_refused_when_the_validator_let_a_traversal_through() {
	let (_guard, data) = data_dir();
	let account = AccountName::new("alice").expect("account");
	std::fs::create_dir_all(data.join("accounts/alice/folders")).expect("tree");
	// A delimiter becomes `&AC8-` on disk, so only a name that is itself a
	// traversal component is left for the containment check to refuse.
	let escaping = MailboxName::Folder("..");
	assert_outside_root(escaping.messages_dir(&account, &data), "messages_dir");
	assert_outside_root(escaping.folder_dir(&account, &data), "folder_dir");
	let separator = MailboxName::Folder("a\\b");
	assert_outside_root(separator.folder_dir(&account, &data), "a backslash");
}

#[test]
fn digest_and_file_joins_are_refused_when_the_name_carries_a_traversal() {
	let (_guard, data) = data_dir();
	let forged = DigestName("../../outside".to_string());
	assert_outside_root(forged.in_dir(&data), "digest in_dir");
	assert_outside_root(forged.lock_in_dir(&data), "digest lock_in_dir");
}

#[cfg(unix)]
#[test]
fn account_root_is_refused_when_the_account_directory_is_a_link_out_of_the_tree() {
	let (guard, data) = data_dir();
	let outside = guard
		.path()
		.canonicalize()
		.expect("canonical")
		.join("outside");
	std::fs::create_dir_all(&outside).expect("outside");
	std::fs::create_dir_all(data.join("accounts")).expect("accounts");
	std::os::unix::fs::symlink(&outside, data.join("accounts/alice")).expect("link");
	let account = AccountName::new("alice").expect("account");
	assert_outside_root(account.root(&data), "linked account directory");
}

#[test]
fn account_name_keeps_the_names_directories_use() {
	for name in [
		"john.doe",
		"J_Smith",
		"Alice",
		"a b",
		"user@example.org",
		"-lead",
	] {
		let account = AccountName::new(name).expect("a safe directory name");
		assert_eq!(account.as_str(), name, "case is preserved");
	}
	let (_guard, data) = data_dir();
	let root = AccountName::new("John.Doe")
		.expect("name")
		.root(&data)
		.expect("root");
	assert_eq!(root.as_path(), data.join("accounts/John.Doe"));
}

#[test]
fn pseudonym_is_short_stable_and_hides_the_value() {
	let id = DigestName::pseudonym("john.doe");
	assert_eq!(id.len(), 12);
	assert_eq!(id, DigestName::pseudonym("john.doe"));
	assert!(!id.contains("john"));
}
