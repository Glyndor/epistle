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

#[test]
fn a_reservation_counts_for_the_delivery_check_until_it_is_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = MailboxQuota::on_disk(dir.path().to_path_buf(), MessageCrypto::disabled(), 1000);
	let directory = directory();
	assert!(!quota.would_overflow(&directory, "bob", 600));
	let held = reserve(dir.path(), "bob", 600);
	assert_eq!(held.reserved(), 600);
	assert_eq!(reserved_bytes(dir.path(), "bob"), 600);
	// 600 reserved and 600 more would be 1200 of 1000: delivery refuses it.
	assert!(quota.would_overflow(&directory, "bob", 600));
	// Another account of the same store is not charged.
	assert!(!quota.would_overflow(&directory, "carol", 600));
	// The second reservation sees the first one, the first never saw the second.
	let second = reserve(dir.path(), "bob", 600);
	assert_eq!(second.reserved(), 1200);
	drop(held);
	drop(second);
	assert_eq!(reserved_bytes(dir.path(), "bob"), 0);
	assert!(!quota.would_overflow(&directory, "bob", 600));
}

/// A writer that is stopped at the point where its bytes are not stored yet
/// stands for a process killed there: the charge it took must not outlive it,
/// and the charge of a sibling that is still writing must stay.
#[tokio::test]
async fn a_writer_stopped_before_it_stored_releases_only_its_own_reservation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().to_path_buf();
	let quota = MailboxQuota::on_disk(data_dir.clone(), MessageCrypto::disabled(), 1000);
	let directory = directory();
	let _sibling = reserve(&data_dir, "bob", 300);
	let (reached, wait_reached) = tokio::sync::oneshot::channel();
	let stopped = tokio::spawn({
		let data_dir = data_dir.clone();
		async move {
			let _held = reserve(&data_dir, "bob", 600);
			let _ = reached.send(());
			std::future::pending::<()>().await;
		}
	});
	wait_reached.await.expect("the writer reserved");
	assert_eq!(reserved_bytes(&data_dir, "bob"), 900);
	assert!(quota.would_overflow(&directory, "bob", 200));
	stopped.abort();
	assert!(stopped.await.expect_err("stopped").is_cancelled());
	assert_eq!(
		reserved_bytes(&data_dir, "bob"),
		300,
		"the stopped writer kept its charge, or took the sibling's with it"
	);
	// The room the stopped writer held is usable again, and no more than that.
	assert!(!quota.would_overflow(&directory, "bob", 700));
	assert!(quota.would_overflow(&directory, "bob", 701));
}

#[test]
fn a_writer_that_panics_with_a_reservation_leaves_the_account_usable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().to_path_buf();
	let quota = MailboxQuota::on_disk(data_dir.clone(), MessageCrypto::disabled(), 1000);
	let directory = directory();
	let crashed = std::thread::spawn({
		let data_dir = data_dir.clone();
		move || {
			let _held = reserve(&data_dir, "bob", 900);
			panic!("the writer dies holding its reservation");
		}
	})
	.join();
	assert!(crashed.is_err());
	assert_eq!(reserved_bytes(&data_dir, "bob"), 0);
	assert!(!quota.would_overflow(&directory, "bob", 1000));
	let next = reserve(&data_dir, "bob", 10);
	assert_eq!(next.reserved(), 10);
}
