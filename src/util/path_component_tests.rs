use super::*;

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
	for name in [
		"alice",
		"Work",
		"Sent Items",
		"a.b",
		"a..b",
		"caf\u{e9}",
		"x-1_y",
	] {
		assert!(is_plain_component(name), "{name:?} must be accepted");
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
	for name in [
		"Alice",
		"a.b",
		"a b",
		"-lead",
		"al\u{ef}ce",
		"user@example.org",
	] {
		assert_eq!(
			AccountName::new(name),
			Err(InvalidComponent),
			"account {name:?} is outside the account alphabet"
		);
	}
	let long = "a".repeat(MAX_ACCOUNT_LEN + 1);
	assert_eq!(AccountName::new(&long), Err(InvalidComponent));
}

#[test]
fn account_name_accepts_what_accounts_use() {
	for name in ["alice", "bob-2", "a", "0day"] {
		let account = AccountName::new(name).expect("valid account");
		assert_eq!(account.as_str(), name);
	}
	let max = "a".repeat(MAX_ACCOUNT_LEN);
	assert!(AccountName::new(&max).is_ok());
}

#[test]
fn account_root_joins_under_accounts() {
	let account = AccountName::new("alice").expect("account");
	let root = account.root(Path::new("/data"));
	assert_eq!(root.as_path(), Path::new("/data/accounts/alice"));
	assert_eq!(
		root.child(FixedDir::Archive),
		PathBuf::from("/data/accounts/alice/.archive")
	);
	assert_eq!(
		root.child(FixedDir::Tmp),
		PathBuf::from("/data/accounts/alice/tmp")
	);
}

#[test]
fn mailbox_name_rejects_dangerous_names() {
	for name in DANGEROUS {
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
		"Archive/2024",
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
	for name in ["Work", "Sent Items", "a-b_c.d", "2024", "a..b"] {
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
	let data = Path::new("/data");
	let account = AccountName::new("alice").expect("account");
	let inbox = MailboxName::new("INBOX").expect("inbox");
	assert_eq!(
		inbox.messages_dir(&account, data),
		PathBuf::from("/data/accounts/alice/new")
	);
	assert_eq!(inbox.folder_dir(&account, data), None);
	let work = MailboxName::new("Work").expect("folder");
	assert_eq!(
		work.messages_dir(&account, data),
		PathBuf::from("/data/accounts/alice/folders/Work/new")
	);
	assert_eq!(
		work.folder_dir(&account, data),
		Some(PathBuf::from("/data/accounts/alice/folders/Work"))
	);
	assert_eq!(
		folders_dir(&account, data),
		PathBuf::from("/data/accounts/alice/folders")
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
	let path = digest.in_dir(Path::new("/d"));
	assert_eq!(path.parent(), Some(Path::new("/d")));
	let lock = digest.lock_in_dir(Path::new("/d"));
	assert_eq!(lock.parent(), Some(Path::new("/d")));
	assert!(lock.to_string_lossy().ends_with(".lock"));
}

#[test]
fn message_and_state_files_have_fixed_names() {
	let dir = Path::new("/m");
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
			message_file(dir, id, ext),
			PathBuf::from(format!("/m/{id}{suffix}"))
		);
		assert_eq!(
			message_tmp_file(dir, id, ext),
			PathBuf::from(format!("/m/{id}{suffix}.tmp"))
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
		assert_eq!(state_file(dir, file), PathBuf::from(format!("/m/{name}")));
		assert_eq!(
			state_tmp_file(dir, file),
			PathBuf::from(format!("/m/{name}.tmp"))
		);
	}
}

#[test]
fn invalid_component_converts_to_invalid_input() {
	let error: std::io::Error = InvalidComponent.into();
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(error.to_string(), "invalid path component");
}
