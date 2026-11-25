//! The tenant and the retention of a submission follow the address it is
//! written under, not the envelope sender a submitter chose among its own.

use std::path::Path;
use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::evidence::MailClass;
use crate::evidence::chain::Chain;
use crate::evidence::policy::{Mode, Policy, Rule, Scope};
use crate::evidence::record::{Entry, Record};
use crate::evidence::service::EvidenceService;
use crate::evidence::verify::walk_day;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, Submission};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

fn rule(tenant: &str, mode: Mode, days: u32) -> Rule {
	Rule {
		scope: Scope::Tenant(tenant.to_string()),
		class: Some(MailClass::Transactional),
		mode,
		days,
	}
}

/// `a` owns `example.org` and keeps metadata for 30 days; `b` owns
/// `other.example` and keeps the whole message for 7.
fn sink(dir: &Path) -> SplitDelivery {
	crate::evidence::policy::save(
		&dir.join("evidence"),
		&Policy {
			rules: vec![rule("a", Mode::Metadata, 30), rule("b", Mode::Full, 7)],
		},
	)
	.expect("policy");
	let tenants = vec![
		("a".to_string(), vec!["example.org".to_string()]),
		("b".to_string(), vec!["other.example".to_string()]),
	];
	let service =
		Arc::new(EvidenceService::open(dir, tenants, MessageCrypto::disabled()).expect("evidence"));
	service.set_gate(None);
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string(), "other.example".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	SplitDelivery::new(dir, directory)
		.expect("sink")
		.with_evidence(service)
}

fn records(dir: &Path) -> Vec<Record> {
	let root = dir.join("evidence");
	let mut out = Vec::new();
	for day in Chain::open(&root).expect("chain").days().expect("days") {
		walk_day(&root, day, None, |_, record, _| out.push(record.clone())).expect("walk");
	}
	out
}

/// Submit one message written under `from`, with `reverse_path` as envelope
/// sender; the tenant it was recorded under and the days it is kept.
fn submitted(from: &str, reverse_path: &str) -> (Option<String>, u32) {
	let dir = tempfile::tempdir().expect("tempdir");
	let split = sink(dir.path());
	let id = uuid::Uuid::now_v7();
	split
		.submit(
			AcceptedMessage {
				reverse_path: reverse_path.into(),
				recipients: vec!["student@example.net".into()],
				data: format!("From: {from}\r\nMessage-ID: <m@example.org>\r\n\r\nbody\r\n")
					.into_bytes(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: true,
				no_dsn: Vec::new(),
			},
			id,
			"alice",
			&Submission::of_class(MailClass::Transactional),
		)
		.expect("accepted");
	let days = FsSpool::open(dir.path())
		.expect("spool")
		.load(id)
		.expect("queued")
		.envelope
		.retain_days;
	let records = records(dir.path());
	let Entry::Accepted(accepted) = &records[0].entry else {
		panic!("not an acceptance");
	};
	(accepted.tenant.clone(), days)
}

#[test]
fn the_envelope_sender_of_another_tenant_does_not_change_the_tenant() {
	assert_eq!(
		submitted("alice@example.org", "alice@other.example"),
		(Some("a".to_string()), 30),
		"written under tenant a: its tenant and its retention, whatever the envelope says"
	);
	assert_eq!(
		submitted("alice@other.example", "alice@example.org"),
		(Some("b".to_string()), 7)
	);
}

#[test]
fn without_a_distinct_envelope_sender_nothing_changes() {
	assert_eq!(
		submitted("alice@example.org", "alice@example.org"),
		(Some("a".to_string()), 30)
	);
}
