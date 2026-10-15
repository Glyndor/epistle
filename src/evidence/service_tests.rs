use super::*;
use crate::evidence::policy::{Mode, Rule, Scope};
use crate::evidence::record::Record;
use crate::evidence::verify::walk_day;

fn service(dir: &Path) -> EvidenceService {
	EvidenceService::open(
		dir,
		vec![("sena".into(), vec!["sena.example".into()])],
		MessageCrypto::disabled(),
	)
	.expect("open")
}

fn records(dir: &Path) -> Vec<Record> {
	let chain = Chain::open(&dir.join("evidence")).expect("chain");
	let mut out = Vec::new();
	for day in chain.days().expect("days") {
		walk_day(&dir.join("evidence"), day, None, |_, record, _| {
			out.push(record.clone())
		})
		.expect("walk");
	}
	out
}

fn submitted<'a>(data: &'a [u8], recipients: &'a [String]) -> Submitted<'a> {
	Submitted {
		spool_id: Uuid::from_u128(7),
		account: "notices",
		class: MailClass::Transactional,
		from: "notices@sena.example",
		recipients,
		data,
	}
}

#[test]
fn an_acceptance_records_the_hash_headers_and_tenant() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let data = b"Message-ID: <1@sena.example>\r\nDate: Wed, 14 Oct 2026 10:00:00 +0000\r\nSubject: Aviso\r\n\r\nbody\r\n";
	let recipients = vec!["student@example.net".to_string()];
	let retention = service
		.retention("notices", "notices@sena.example", MailClass::Transactional)
		.expect("transactional keeps evidence");
	service
		.accept(&submitted(data, &recipients), retention)
		.expect("accept");
	let records = records(dir.path());
	let Entry::Accepted(accepted) = &records[0].entry else {
		panic!("not an acceptance");
	};
	assert_eq!(accepted.sha256, to_hex(&sha256(data)));
	assert_eq!(accepted.subject.as_deref(), Some("Aviso"));
	assert_eq!(accepted.message_id.as_deref(), Some("<1@sena.example>"));
	assert_eq!(accepted.tenant.as_deref(), Some("sena"));
	assert_eq!(accepted.recipients, recipients);
}

#[test]
fn personal_mail_keeps_nothing_by_default_and_a_tenant_rule_applies() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	assert_eq!(
		service.retention("a", "a@other.example", MailClass::Personal),
		None
	);
	let mut policy = Policy::default();
	policy.set(Rule {
		scope: Scope::Tenant("sena".into()),
		class: Some(MailClass::Transactional),
		mode: Mode::Full,
		days: 30,
	});
	super::super::policy::save(service.root(), &policy).expect("save");
	service.reload();
	let full = service
		.retention("notices", "notices@sena.example", MailClass::Transactional)
		.expect("kept");
	assert_eq!((full.mode, full.days), (RetentionMode::Full, 30));
	let outside = service
		.retention("other", "other@other.example", MailClass::Transactional)
		.expect("kept");
	assert_eq!((outside.mode, outside.days), (RetentionMode::Metadata, 365));
}

#[test]
fn a_full_retention_keeps_the_exact_bytes_sealed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = MessageCrypto::for_test(&crate::test_fixtures::bytes::<32>());
	let service = EvidenceService::open(dir.path(), Vec::new(), key.clone()).expect("open");
	let data = b"Subject: kept\r\n\r\nbody\r\n";
	let recipients = vec!["a@example.net".to_string()];
	let retention = Retention {
		mode: RetentionMode::Full,
		days: 30,
	};
	service
		.accept(&submitted(data, &recipients), retention)
		.expect("accept");
	let day = super::super::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	let path = dir
		.path()
		.join("evidence/messages")
		.join(day.name())
		.join("30")
		.join(format!("{}.eml", Uuid::from_u128(7)));
	let stored = std::fs::read(&path).expect("kept");
	assert!(stored != data, "kept in the clear under encrypt_at_rest");
	let opened = key
		.decode_with_aad(&stored, Uuid::from_u128(7).as_bytes())
		.expect("decrypt");
	assert!(opened == data, "the kept bytes differ from those queued");
}

#[test]
fn an_unreadable_policy_keeps_the_last_good_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	std::fs::write(service.root().join("policy.json"), "{").expect("corrupt");
	service.reload();
	assert!(service.policy_error().is_some());
	assert!(
		service
			.retention("a", "a@x.example", MailClass::Transactional)
			.is_some()
	);
}

#[test]
fn the_gate_holds_and_releases() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	assert_eq!(service.held(), None);
	service.set_gate(Some("the chain is broken".into()));
	assert_eq!(service.held().as_deref(), Some("the chain is broken"));
	service.set_gate(None);
	assert_eq!(service.held(), None);
}
