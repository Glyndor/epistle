//! Delivery admission holds one quota domain through the write result.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn directory() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
			("other-bob@example.org".to_string(), "bob".to_string()),
		],
	)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_admissions_fill_the_quota_exactly() {
	let usage = Arc::new(AtomicU64::new(0));
	let probe = usage.clone();
	let quota = Arc::new(MailboxQuota::new(
		move |_| probe.load(Ordering::SeqCst),
		700,
	));
	let directory = Arc::new(directory());
	let start = Arc::new(tokio::sync::Barrier::new(64));
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..64 {
		let (quota, directory, usage, start) = (
			quota.clone(),
			directory.clone(),
			usage.clone(),
			start.clone(),
		);
		tasks.spawn(async move {
			start.wait().await;
			let lock = quota.delivery_lock("bob");
			let _held = lock.lock().expect("account lock");
			if quota.would_overflow(&directory, "bob", 100) {
				return false;
			}
			// Keep the guard while another delivery has an opportunity to run.
			std::thread::yield_now();
			usage.fetch_add(100, Ordering::SeqCst);
			true
		});
	}
	let mut accepted = 0;
	while let Some(result) = tasks.join_next().await {
		accepted += usize::from(result.expect("admission task"));
	}
	assert_eq!(accepted, 7);
	assert_eq!(usage.load(Ordering::SeqCst), 700);
}

#[test]
fn a_held_account_leaves_other_accounts_available() {
	let quota = MailboxQuota::new(|_| 0, 100);
	let lock = quota.delivery_lock("bob");
	let held = lock.lock().expect("account lock");
	let same = quota.delivery_lock("bob");
	assert!(same.try_lock().is_err());
	let other = quota.delivery_lock("carol");
	assert!(
		other.try_lock().is_ok(),
		"another account must remain available"
	);
	drop(held);
	assert!(
		same.try_lock().is_ok(),
		"the account must be available after release"
	);
}

#[test]
fn a_failed_write_releases_admission_without_charging_bytes() {
	let usage = Arc::new(AtomicU64::new(0));
	let probe = usage.clone();
	let quota = MailboxQuota::new(move |_| probe.load(Ordering::SeqCst), 100);
	let directory = directory();
	let result: Result<(), &str> = {
		let lock = quota.delivery_lock("bob");
		let _held = lock.lock().expect("account lock");
		assert!(!quota.would_overflow(&directory, "bob", 100));
		Err("write failed")
	};
	assert_eq!(result, Err("write failed"));
	let retry = quota.delivery_lock("bob");
	let _held = retry
		.try_lock()
		.expect("a failed write must release admission");
	assert!(!quota.would_overflow(&directory, "bob", 100));
	usage.store(100, Ordering::SeqCst);
	assert!(quota.would_overflow(&directory, "bob", 1));
}

#[test]
fn listeners_share_admission_only_for_the_same_mail_store() {
	let root = tempfile::tempdir().expect("mail store");
	let other_root = tempfile::tempdir().expect("other mail store");
	let first = MailboxQuota::on_disk(root.path().to_path_buf(), MessageCrypto::disabled(), 100);
	let second = MailboxQuota::on_disk(root.path().join("."), MessageCrypto::disabled(), 100);
	let other = MailboxQuota::on_disk(
		other_root.path().to_path_buf(),
		MessageCrypto::disabled(),
		100,
	);
	let lock = first.delivery_lock("bob");
	let held = lock.lock().expect("account lock");
	let shared = second.delivery_lock("bob");
	assert!(shared.try_lock().is_err());
	let separate = other.delivery_lock("bob");
	assert!(
		separate.try_lock().is_ok(),
		"another mail store must remain available"
	);
	drop(held);
	assert!(
		shared.try_lock().is_ok(),
		"the shared account must be available after release"
	);
}
