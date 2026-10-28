//! A transactional message from submission to a bundle a third party
//! checks, through the real sink, queue worker, sealing, timestamping,
//! export and check, with nothing but the bundle and two published keys at
//! the end.

use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::evidence::MailClass;
use crate::evidence::audit::{Options, verify};
use crate::evidence::bundle::{Selector, check, export};
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::sha256;
use crate::evidence::service::EvidenceService;
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::queue::{SuppressionList, Worker};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink, Submission};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

#[tokio::test]
async fn a_notice_is_submitted_delivered_sealed_stamped_exported_and_checked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("notices@example.org".to_string(), "notices".to_string())],
	));
	let service = Arc::new(
		EvidenceService::open(dir.path(), Vec::new(), MessageCrypto::disabled()).expect("service"),
	);
	service.set_gate(None);
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_evidence(Arc::clone(&service));
	let message = AcceptedMessage {
		reverse_path: "notices@example.org".into(),
		recipients: vec!["student@remote.example".into()],
		data: b"Message-ID: <e2e@example.org>\r\nSubject: Retiro\r\n\r\nYou were withdrawn.\r\n"
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
			uuid::Uuid::now_v7(),
			"notices",
			&Submission::of_class(MailClass::Transactional),
		)
		.expect("accepted");
	let remote = FakeRemote::default();
	remote.script("remote.example", Script::default());
	Worker::new(
		FsSpool::open(dir.path()).expect("spool"),
		Arc::new(remote),
		"mail.example.org",
	)
	.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
	.with_suppression(SuppressionList::open(dir.path()).expect("suppression"))
	.with_evidence(Arc::clone(&service))
	.pass()
	.await
	.expect("pass");

	// Two days later the day is sealed with the key, and the authority
	// stamps the seal.
	let today = Day::of_epoch(crate::storage::delivery_log::now_epoch());
	let sealed_at = Day(today.0 + 1).start_epoch() + 60;
	let key = EvidenceKey::load_or_create(service.root()).expect("key");
	let tsa = FakeTsa::new(sealed_at + 3600);
	seal_closed_days(service.root(), &key, true, sealed_at).expect("seal");
	let paths = files(service.root(), today);
	let sealed = std::fs::read(&paths.json).expect("seal");
	std::fs::write(
		&paths.tsr,
		tsa.respond(&build(&sha256(&sealed), random_nonce()).der),
	)
	.expect("token");
	let report = verify(
		service.root(),
		&Options {
			from: None,
			to: None,
			anchors: vec![tsa.anchor],
			now: sealed_at + 7200,
		},
	)
	.expect("verify");
	assert_eq!(report.first_break, None);
	assert_eq!((report.records, report.sealed, report.stamped), (2, 1, 1));

	// What a third party receives: the bundle, and the key's fingerprint.
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	export(
		service.root(),
		&MessageCrypto::disabled(),
		&Selector::MessageId("<e2e@example.org>".into()),
		&bundle,
	)
	.expect("export");
	let checked = check(&bundle, &[tsa.anchor], &[key.id()]).expect("check");
	let failed: Vec<_> = checked
		.findings
		.iter()
		.filter_map(|finding| finding.result.as_ref().err())
		.collect();
	assert!(failed.is_empty(), "{failed:?}");
	let records = std::fs::read_to_string(bundle.join(format!("records/{}.jsonl", today.name())))
		.expect("records");
	assert!(records.contains("\"kind\":\"accepted\""), "no acceptance");
	assert!(records.contains("\"result\":\"delivered\""), "no outcome");
}
