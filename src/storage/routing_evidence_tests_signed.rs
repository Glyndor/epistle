//! The evidence is over the bytes that were queued, DKIM signature included,
//! whoever else the message is for.

use std::io::Write;
use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::evidence::MailClass;
use crate::evidence::chain::Chain;
use crate::evidence::policy::{Mode, Policy, Rule, Scope, save};
use crate::evidence::record::{Entry, sha256, to_hex};
use crate::evidence::service::EvidenceService;
use crate::evidence::verify::walk_day;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, Submission};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("notices@example.org".to_string(), "notices".to_string())],
	))
}

/// A sink that signs, keeps full messages, and the id it queued under.
fn submit(dir: &std::path::Path, recipients: &[&str]) -> uuid::Uuid {
	let mut policy = Policy::default();
	policy.set(Rule {
		scope: Scope::Server,
		class: Some(MailClass::Transactional),
		mode: Mode::Full,
		days: 30,
	});
	save(&dir.join("evidence"), &policy).expect("policy");
	let service = Arc::new(
		EvidenceService::open(dir, Vec::new(), MessageCrypto::disabled()).expect("evidence"),
	);
	service.set_gate(None);
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let mut file = tempfile::NamedTempFile::new().expect("file");
	file.write_all(pem.as_bytes()).expect("pem");
	let signer = Arc::new(crate::dkim::Signer::load("sel", file.path()).expect("signer"));
	let split = SplitDelivery::new(dir, directory())
		.expect("sink")
		.with_evidence(Arc::clone(&service))
		.with_signer(crate::dkim::PerDomainSigner::new(
			crate::dkim::ReloadableSigner::new(signer),
			Vec::new(),
		));
	let id = uuid::Uuid::now_v7();
	let message = AcceptedMessage {
		reverse_path: "notices@example.org".into(),
		recipients: recipients.iter().map(ToString::to_string).collect(),
		data: b"From: notices@example.org\r\nMessage-ID: <m@example.org>\r\nSubject: Aviso\r\n\r\nbody\r\n"
			.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	split
		.submit(
			message,
			id,
			"notices",
			&Submission::of_class(MailClass::Transactional),
		)
		.expect("accepted");
	id
}

/// The acceptance recorded for `id`: its hash and the kept bytes.
fn recorded(dir: &std::path::Path, id: uuid::Uuid) -> (String, Vec<u8>) {
	let root = dir.join("evidence");
	let mut hash = String::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		walk_day(&root, day, None, |_, record, _| {
			if let Entry::Accepted(accepted) = &record.entry
				&& accepted.spool_id == id
			{
				hash = accepted.sha256.clone();
			}
		})
		.expect("walk");
	}
	let mut kept = Vec::new();
	let messages = root.join("messages");
	let mut pending = vec![messages];
	while let Some(path) = pending.pop() {
		for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else if path
				.file_name()
				.is_some_and(|n| n == format!("{id}.eml").as_str())
			{
				kept = std::fs::read(&path).expect("kept");
			}
		}
	}
	(hash, kept)
}

#[test]
fn the_record_and_the_kept_message_are_the_signed_bytes_whoever_the_recipients_are() {
	for recipients in [
		vec!["student@remote.example"],
		vec!["notices@example.org", "student@remote.example"],
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let id = submit(dir.path(), &recipients);
		let queued = FsSpool::open(dir.path())
			.expect("spool")
			.load(id)
			.expect("queued");
		assert!(
			queued.data.starts_with(b"DKIM-Signature:"),
			"{recipients:?}: not signed"
		);
		let (hash, kept) = recorded(dir.path(), id);
		assert_eq!(
			hash,
			to_hex(&sha256(&queued.data)),
			"{recipients:?}: the hash"
		);
		assert_eq!(kept, queued.data, "{recipients:?}: the kept message");
	}
}
