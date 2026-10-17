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
	assert_eq!(
		service.held().as_deref(),
		Some(NOT_VERIFIED_YET),
		"closed until a verification opens it"
	);
	service.set_gate(Some("the chain is broken".into()));
	assert_eq!(service.held().as_deref(), Some("the chain is broken"));
	service.set_gate(None);
	assert_eq!(service.held(), None);
}

#[test]
fn an_open_gate_closes_again_when_no_verification_follows() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	service.set_gate_for(None, std::time::Duration::ZERO);
	let held = service.held().expect("a stale verification holds");
	assert!(held.contains("has not been verified in the last"), "{held}");
	service.set_gate(None);
	assert_eq!(service.held(), None);
}

#[test]
fn the_bytes_of_an_acceptance_that_was_refused_do_not_stay_for_the_retention() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	// The log cannot take today's record.
	let today = super::super::day::Day::of_epoch(service.time().read().time);
	std::fs::create_dir_all(
		dir.path()
			.join("evidence/chain")
			.join(format!("{}.jsonl", today.name())),
	)
	.expect("block the day");
	let recipients = vec!["a@example.net".to_string()];
	let retention = Retention {
		mode: RetentionMode::Full,
		days: 365,
	};
	for _ in 0..3 {
		service
			.accept(&submitted(&[b'x'; 4096], &recipients), retention)
			.expect_err("the record is refused");
	}
	let left: Vec<_> = walk_kept(&dir.path().join("evidence/messages"));
	assert_eq!(left, Vec::<std::path::PathBuf>::new(), "bytes were left");
}

fn walk_kept(root: &Path) -> Vec<std::path::PathBuf> {
	let mut found = Vec::new();
	let mut pending = vec![root.to_path_buf()];
	while let Some(dir) = pending.pop() {
		let Ok(entries) = std::fs::read_dir(&dir) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			match path.is_dir() {
				true => pending.push(path),
				false => found.push(path),
			}
		}
	}
	found
}

#[test]
fn the_bytes_stay_when_the_record_may_have_been_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	// The head cannot be written after the record was synced: the record is
	// durable, and the call still fails.
	std::fs::create_dir(crate::evidence::head::path(&dir.path().join("evidence")))
		.expect("block the head");
	let recipients = vec!["a@example.net".to_string()];
	let retention = Retention {
		mode: RetentionMode::Full,
		days: 365,
	};
	let error = service
		.accept(&submitted(&[b'x'; 64], &recipients), retention)
		.expect_err("the head is blocked");
	assert!(crate::evidence::chain::Unconfirmed::is(&error), "{error}");
	assert_eq!(records(dir.path()).len(), 1, "the record is on disk");
	let kept = walk_kept(&dir.path().join("evidence/messages"));
	assert_eq!(kept.len(), 1, "the record's message was destroyed");
}

fn limited(dir: &Path, account_records: u64, day_records: u64) -> EvidenceService {
	service(dir).with_limits(crate::evidence::quota::Limits {
		account_records,
		account_kept_bytes: 10_000,
		day_records,
	})
}

fn from<'a>(
	account: &'static str,
	n: u128,
	recipients: &'a [String],
	data: &'a [u8],
) -> Submitted<'a> {
	Submitted {
		spool_id: Uuid::from_u128(n),
		account,
		..submitted(data, recipients)
	}
}

const METADATA: Retention = Retention {
	mode: RetentionMode::Metadata,
	days: 30,
};

#[test]
fn one_account_flooding_the_log_is_refused_and_the_others_are_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Each message owes two records: its own and one outcome.
	let service = limited(dir.path(), 10, 100);
	let recipients = vec!["a@example.net".to_string()];
	for n in 0..5 {
		service
			.accept(&from("noisy", n, &recipients, b"x"), METADATA)
			.expect("within");
	}
	let refused = service
		.accept(&from("noisy", 5, &recipients, b"x"), METADATA)
		.expect_err("past the account's limit");
	assert_eq!(
		refused.kind(),
		std::io::ErrorKind::QuotaExceeded,
		"{refused}"
	);
	service
		.accept(&from("quiet", 6, &recipients, b"x"), METADATA)
		.expect("another account is not held up");
	assert_eq!(records(dir.path()).len(), 6, "the refused one was recorded");
	assert!(
		service.quota_warning().is_some(),
		"no warning near the limit"
	);
}

#[test]
fn concurrent_submissions_of_one_account_cannot_all_pass_the_check_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let threads = 8u64;
	// Room for seven of the eight, at two records each.
	let service = std::sync::Arc::new(limited(dir.path(), (threads - 1) * 2, 1000));
	let recipients = vec!["a@example.net".to_string()];
	let start = std::sync::Arc::new(std::sync::Barrier::new(threads as usize));
	let handles: Vec<_> = (0..threads)
		.map(|n| {
			let (service, start, recipients) = (
				std::sync::Arc::clone(&service),
				std::sync::Arc::clone(&start),
				recipients.clone(),
			);
			std::thread::spawn(move || {
				start.wait();
				service
					.accept(&from("noisy", u128::from(n), &recipients, b"x"), METADATA)
					.is_ok()
			})
		})
		.collect();
	let admitted = handles
		.into_iter()
		.map(|handle| handle.join().expect("thread"))
		.filter(|admitted| *admitted)
		.count();
	assert_eq!(admitted as u64, threads - 1, "the quota was passed");
	assert_eq!(records(dir.path()).len() as u64, threads - 1);
}

#[test]
fn room_reserved_for_a_record_that_was_not_written_is_given_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = limited(dir.path(), 2, 100);
	let recipients = vec!["a@example.net".to_string()];
	let today = super::super::day::Day::of_epoch(service.time().read().time);
	// The quota reads the log on first use: let it, before the log is blocked.
	assert_eq!(service.quota_warning(), None);
	let blocked = dir
		.path()
		.join("evidence/chain")
		.join(format!("{}.jsonl", today.name()));
	std::fs::create_dir_all(&blocked).expect("block the day");
	for n in 0..3 {
		let refused = service
			.accept(&from("a", n, &recipients, b"x"), METADATA)
			.expect_err("the log refuses");
		assert_ne!(
			refused.kind(),
			std::io::ErrorKind::QuotaExceeded,
			"attempt {n}"
		);
	}
	std::fs::remove_dir(&blocked).expect("unblock");
	service
		.accept(&from("a", 9, &recipients, b"x"), METADATA)
		.expect("the failed attempts did not use the room up");
}

#[test]
fn room_stays_reserved_when_the_record_may_have_been_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = limited(dir.path(), 2, 100);
	let recipients = vec!["a@example.net".to_string()];
	std::fs::create_dir(crate::evidence::head::path(&dir.path().join("evidence")))
		.expect("block the head");
	let first = service
		.accept(&from("a", 1, &recipients, b"x"), METADATA)
		.expect_err("the head is blocked");
	assert!(crate::evidence::chain::Unconfirmed::is(&first));
	let second = service
		.accept(&from("a", 2, &recipients, b"x"), METADATA)
		.expect_err("the first may be on disk and counts");
	assert_eq!(second.kind(), std::io::ErrorKind::QuotaExceeded);
}

#[test]
fn an_account_with_many_recipients_cannot_use_up_the_room_of_the_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A tenth of the day each, as the defaults.
	let service = limited(dir.path(), 1000, 10_000);
	let many: Vec<String> = (0..100).map(|n| format!("r{n}@example.net")).collect();
	let one = vec!["a@example.net".to_string()];
	let mut sent = 0;
	while service
		.accept(&from("noisy", 100 + sent, &many, b"x"), METADATA)
		.is_ok()
	{
		sent += 1;
		assert!(sent < 100, "never refused");
	}
	service
		.accept(&from("other", 1, &one, b"x"), METADATA)
		.expect("another account is not held up");
}

#[test]
fn the_bytes_an_account_may_keep_are_bounded_and_nothing_is_written_past_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path()).with_limits(crate::evidence::quota::Limits {
		account_records: 100,
		account_kept_bytes: 1000,
		day_records: 100,
	});
	let recipients = vec!["a@example.net".to_string()];
	let full = Retention {
		mode: RetentionMode::Full,
		days: 30,
	};
	service
		.accept(&submitted(&[b'x'; 600], &recipients), full)
		.expect("within the bytes");
	let big = Submitted {
		spool_id: Uuid::from_u128(8),
		..submitted(&[b'y'; 600], &recipients)
	};
	service.accept(&big, full).expect_err("past the bytes");
	assert_eq!(
		walk_kept(&dir.path().join("evidence/messages")).len(),
		1,
		"bytes were written past the limit"
	);
}

#[test]
fn a_second_server_on_the_same_evidence_directory_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = EvidenceService::open(dir.path(), Vec::new(), MessageCrypto::disabled())
		.expect("the first server opens");
	let error = EvidenceService::open(dir.path(), Vec::new(), MessageCrypto::disabled())
		.expect_err("the second must not open without the lock");
	assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
	// When the first stops, the directory is free again.
	drop(first);
	EvidenceService::open(dir.path(), Vec::new(), MessageCrypto::disabled())
		.expect("opens after the first stopped");
}

#[test]
fn a_lock_that_cannot_be_taken_is_an_error_not_a_server_nobody_believes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = root_of(dir.path());
	std::fs::create_dir_all(&root).expect("root");
	// A link in the place of the lock file is refused (O_NOFOLLOW).
	std::os::unix::fs::symlink("elsewhere", root.join("server.lock")).expect("link");
	let error = EvidenceService::open(dir.path(), Vec::new(), MessageCrypto::disabled())
		.expect_err("the lock could not be taken");
	assert_ne!(error.kind(), std::io::ErrorKind::WouldBlock);
}
