//! The whole run: refusals before any write, the message in the spool, the
//! rate record, the report and the exit code.

use std::process::ExitCode;
use std::time::Duration;

use super::support::*;
use crate::cli::deliverability::guard::{Guard, MIN_INTERVAL_SECS};
use crate::cli::deliverability::{Env, Signing, TestArgs, execute, signing_of};
use crate::storage::MessageCrypto;

const T: u64 = 1_800_000_000;

struct Fixture {
	dir: tempfile::TempDir,
	config: crate::config::Config,
	store: crate::directory_store::AccountStore,
	signer: Option<crate::dkim::PerDomainSigner>,
}

impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("dir");
		let config = config(dir.path());
		let store = store(dir.path(), &config, Vec::new());
		let signer = Some(signer(dir.path()));
		Self {
			dir,
			config,
			store,
			signer,
		}
	}

	async fn run(&self, yes: bool, json: bool, now: u64) -> (ExitCode, String) {
		let env = Env {
			config: &self.config,
			store: &self.store,
			signer: self.signer.as_ref(),
			crypto: MessageCrypto::disabled(),
			now: Some(now),
			poll: Duration::from_millis(1),
		};
		let args = TestArgs {
			account: "alice".into(),
			to: DESTINATION.into(),
			yes,
			wait: 0,
			json,
		};
		let mut out = Vec::new();
		let code = execute(&env, &args, &mut out).await;
		(code, String::from_utf8(out).expect("utf8"))
	}

	fn queued(&self) -> Vec<std::path::PathBuf> {
		let new = self.dir.path().join("spool/new");
		match std::fs::read_dir(new) {
			Ok(entries) => entries
				.flatten()
				.map(|entry| entry.path())
				.filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
				.collect(),
			Err(_) => Vec::new(),
		}
	}

	fn state_file(&self) -> std::path::PathBuf {
		self.dir.path().join("deliverability-test.json")
	}
}

#[tokio::test]
async fn without_yes_nothing_is_sent_or_recorded() {
	let fixture = Fixture::new();
	let (code, out) = fixture.run(false, false, T).await;
	assert_eq!(code, ExitCode::from(2));
	assert!(out.contains("would send one test message"), "{out}");
	assert!(out.contains(DESTINATION));
	assert!(fixture.queued().is_empty());
	assert!(!fixture.state_file().exists());
}

#[tokio::test]
async fn with_yes_a_signed_message_is_queued_and_the_result_is_reported() {
	let fixture = Fixture::new();
	let (code, out) = fixture.run(true, false, T).await;
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	let queued = fixture.queued();
	assert_eq!(queued.len(), 1);
	let data = std::fs::read_to_string(&queued[0]).expect("message");
	assert!(data.starts_with("DKIM-Signature:"), "{data}");
	assert!(data.contains("From: alice@example.org\r\nTo: check@mail-tester.example\r\n"));
	assert!(out.contains("delivery  queued"), "{out}");
	assert!(out.contains("no reputation"), "{out}");
	assert!(fixture.state_file().exists());
}

#[tokio::test]
async fn a_second_run_inside_a_minute_queues_nothing() {
	let fixture = Fixture::new();
	assert_eq!(fixture.run(true, false, T).await.0, ExitCode::SUCCESS);
	let (code, _) = fixture.run(true, false, T + 59).await;
	assert_eq!(code, ExitCode::from(3));
	assert_eq!(fixture.queued().len(), 1);
	assert_eq!(fixture.run(true, false, T + 60).await.0, ExitCode::SUCCESS);
	assert_eq!(fixture.queued().len(), 2);
}

#[tokio::test]
async fn a_refused_run_does_not_spend_the_minute() {
	let fixture = Fixture::new();
	let env = Env {
		config: &fixture.config,
		store: &fixture.store,
		signer: fixture.signer.as_ref(),
		crypto: MessageCrypto::disabled(),
		now: Some(T),
		poll: Duration::from_millis(1),
	};
	let args = TestArgs {
		account: "alice".into(),
		to: "bob@example.org".into(),
		yes: true,
		wait: 0,
		json: false,
	};
	assert_eq!(
		execute(&env, &args, &mut Vec::new()).await,
		ExitCode::from(2)
	);
	assert!(!fixture.state_file().exists());
	assert!(fixture.queued().is_empty());
	assert_eq!(fixture.run(true, false, T).await.0, ExitCode::SUCCESS);
}

#[tokio::test]
async fn an_unsigned_message_is_queued_without_a_signature() {
	let mut fixture = Fixture::new();
	fixture.signer = None;
	let (code, out) = fixture.run(true, false, T).await;
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	let queued = fixture.queued();
	assert_eq!(queued.len(), 1);
	let data = std::fs::read_to_string(&queued[0]).expect("message");
	assert!(!data.starts_with("DKIM-Signature:"), "{data}");
}

#[tokio::test]
async fn the_json_report_is_one_object() {
	let fixture = Fixture::new();
	let (code, out) = fixture.run(true, true, T).await;
	assert_eq!(code, ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_str(out.trim()).expect("one json object");
	assert_eq!(value["to"], DESTINATION);
	assert_eq!(value["delivery"]["state"], "queued");
}

#[tokio::test]
async fn the_report_holds_no_secret() {
	let fixture = Fixture::new();
	let (_, out) = fixture.run(true, false, T).await;
	assert!(!out.contains("PRIVATE KEY"));
	assert!(!out.contains("argon2"));
}

#[tokio::test]
async fn without_yes_and_with_json_stdout_is_one_json_document() {
	let fixture = Fixture::new();
	let (code, out) = fixture.run(false, true, T).await;
	assert_eq!(code, ExitCode::from(2), "{out}");
	let document: serde_json::Value = serde_json::from_str(out.trim()).expect("one JSON document");
	assert_eq!(document["would_send"], true);
	assert_eq!(document["to"], DESTINATION);
	assert!(fixture.queued().is_empty());
}

#[test]
fn a_message_that_could_not_be_signed_is_told_apart_from_one_with_no_key() {
	assert_eq!(signing_of(true, true), Signing::Signed);
	assert_eq!(signing_of(false, false), Signing::NoKey);
	assert_eq!(signing_of(true, false), Signing::Failed);
}

#[test]
fn the_wait_for_the_lock_is_not_counted_against_the_run_that_waited() {
	// The first run holds the lock and records at T; the second took its
	// reading of the clock only after it got the lock, a minute later.
	let dir = tempfile::tempdir().expect("dir");
	let first = Guard::lock(dir.path())
		.expect("lock")
		.checked(T)
		.expect("first");
	first.record(T).expect("record");
	let second = Guard::lock(dir.path()).expect("lock again");
	assert!(second.checked(T + MIN_INTERVAL_SECS).is_ok());
}
