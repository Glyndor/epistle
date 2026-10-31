//! Delivery admission holds one quota domain through the write result.

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

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

fn recipients(names: &[&str]) -> Vec<String> {
	names
		.iter()
		.map(|name| format!("{name}@example.org"))
		.collect()
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
			let _held = quota.lock_delivery(&directory, &recipients(&["bob"])).await;
			if quota.would_overflow(&directory, "bob", 100) {
				return false;
			}
			// Keep the guard while another delivery has an opportunity to run.
			tokio::task::yield_now().await;
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

#[tokio::test]
async fn a_held_account_leaves_other_accounts_available() {
	let quota = MailboxQuota::new(|_| 0, 100);
	let directory = directory();
	let held = quota.lock_delivery(&directory, &recipients(&["bob"])).await;
	let same_recipients = recipients(&["other-bob"]);
	let other_recipients = recipients(&["carol"]);
	let mut same = Box::pin(quota.lock_delivery(&directory, &same_recipients));
	assert!(matches!(
		std::future::poll_fn(|cx| Poll::Ready(same.as_mut().poll(cx))).await,
		Poll::Pending
	));
	let mut other = Box::pin(quota.lock_delivery(&directory, &other_recipients));
	let Poll::Ready(other_held) =
		std::future::poll_fn(|cx| Poll::Ready(other.as_mut().poll(cx))).await
	else {
		panic!("another account must remain available");
	};
	drop(other_held);
	drop(held);
	let Poll::Ready(_) = std::future::poll_fn(|cx| Poll::Ready(same.as_mut().poll(cx))).await
	else {
		panic!("the account must be available after release");
	};
}

#[tokio::test]
async fn a_failed_write_releases_admission_without_charging_bytes() {
	let usage = Arc::new(AtomicU64::new(0));
	let probe = usage.clone();
	let quota = MailboxQuota::new(move |_| probe.load(Ordering::SeqCst), 100);
	let directory = directory();
	let recipients = recipients(&["bob", "other-bob"]);
	let result: Result<(), &str> = async {
		let held = quota.lock_delivery(&directory, &recipients).await;
		assert_eq!(held.len(), 1, "one lock per quota domain");
		assert!(!quota.would_overflow(&directory, "bob", 100));
		Err("write failed")
	}
	.await;
	assert_eq!(result, Err("write failed"));
	let mut retry = Box::pin(quota.lock_delivery(&directory, &recipients));
	let Poll::Ready(_held) = std::future::poll_fn(|cx| Poll::Ready(retry.as_mut().poll(cx))).await
	else {
		panic!("a failed write must release admission");
	};
	assert!(!quota.would_overflow(&directory, "bob", 100));
	usage.store(100, Ordering::SeqCst);
	assert!(quota.would_overflow(&directory, "bob", 1));
}

#[tokio::test]
async fn listeners_share_admission_only_for_the_same_mail_store() {
	let root = tempfile::tempdir().expect("mail store");
	let other_root = tempfile::tempdir().expect("other mail store");
	let first = MailboxQuota::on_disk(root.path().to_path_buf(), MessageCrypto::disabled(), 100);
	let second = MailboxQuota::on_disk(root.path().join("."), MessageCrypto::disabled(), 100);
	let other = MailboxQuota::on_disk(
		other_root.path().to_path_buf(),
		MessageCrypto::disabled(),
		100,
	);
	let directory = directory();
	let recipients = recipients(&["bob"]);
	let held = first.lock_delivery(&directory, &recipients).await;
	let mut shared = Box::pin(second.lock_delivery(&directory, &recipients));
	assert!(matches!(
		std::future::poll_fn(|cx| Poll::Ready(shared.as_mut().poll(cx))).await,
		Poll::Pending
	));
	let mut separate = Box::pin(other.lock_delivery(&directory, &recipients));
	let Poll::Ready(_separate) =
		std::future::poll_fn(|cx| Poll::Ready(separate.as_mut().poll(cx))).await
	else {
		panic!("another mail store must remain available");
	};
	drop(held);
	let Poll::Ready(_) = std::future::poll_fn(|cx| Poll::Ready(shared.as_mut().poll(cx))).await
	else {
		panic!("the shared account must be available after release");
	};
}
