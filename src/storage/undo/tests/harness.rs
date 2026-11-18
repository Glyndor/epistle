//! A routing sink on a temporary data directory with the undo sink in front
//! of it, and a releaser behind.

use std::sync::Arc;

use uuid::Uuid;

use crate::config::Config;
use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, Submission};
use crate::storage::undo::{NoticeStyle, Releaser, UndoPolicy, UndoSink, UndoStore};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

pub(super) fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// A configuration holding `section` under a tenant `acme` that owns
/// `example.org`. It is parsed, not validated: a test may want a value the
/// validation refuses.
pub(super) fn config(section: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.org\"]\n{section}"
	))
	.expect("parse")
}

pub(super) struct Rig {
	pub dir: tempfile::TempDir,
	pub store: Arc<UndoStore>,
	pub sink: UndoSink,
	pub releaser: Releaser,
}

pub(super) fn rig(section: &str) -> Rig {
	rig_with(section, MessageCrypto::disabled())
}

pub(super) fn rig_with(section: &str, crypto: MessageCrypto) -> Rig {
	let dir = tempfile::tempdir().expect("tempdir");
	let routing: Arc<dyn MessageSink> = Arc::new(
		SplitDelivery::new_with_crypto(dir.path(), directory(), crypto.clone()).expect("routing"),
	);
	let store = Arc::new(UndoStore::open(dir.path(), crypto).expect("store"));
	let policy = UndoPolicy::from_config(&config(section));
	let sink = UndoSink::new(
		Arc::clone(&routing),
		Arc::clone(&store),
		policy,
		directory(),
	);
	let releaser = Releaser::new(Arc::clone(&store), routing, style());
	Rig {
		dir,
		store,
		sink,
		releaser,
	}
}

pub(super) fn style() -> NoticeStyle {
	NoticeStyle {
		hostname: "mail.example.org".into(),
		auto_submitted: true,
		auto_response_suppress: true,
	}
}

pub(super) fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nthe secret body\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

/// Submit as `account` and return the id and the time it is released.
pub(super) fn submit(rig: &Rig, account: &str, recipients: &[&str]) -> (Uuid, u64) {
	let id = Uuid::now_v7();
	rig.sink
		.submit(message(recipients), id, account, &Submission::default())
		.expect("submit");
	let release_at = rig
		.store
		.lookup(id)
		.expect("lookup")
		.map_or(0, |(_, at)| at);
	(id, release_at)
}

pub(super) fn inbox_count(root: &std::path::Path, account: &str) -> usize {
	std::fs::read_dir(root.join("accounts").join(account).join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

pub(super) fn spool_ids(root: &std::path::Path) -> Vec<Uuid> {
	FsSpool::open(root).expect("spool").list().expect("list")
}
