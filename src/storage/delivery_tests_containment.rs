//! Delivery builds its own paths, so a hostile account or mailbox name must
//! stop there instead of depending on the caller having validated it.

use super::tests::{directory, message};
use super::*;

fn listing(dir: &std::path::Path) -> Vec<String> {
	let mut names: Vec<String> = fs::read_dir(dir)
		.expect("read_dir")
		.map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
		.collect();
	names.sort();
	names
}

fn sink() -> (tempfile::TempDir, std::path::PathBuf, LocalDelivery) {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	fs::create_dir_all(&data).expect("data dir");
	let sink = LocalDelivery::new(&data, directory()).expect("delivery");
	(outer, data, sink)
}

#[test]
fn a_traversing_account_name_delivers_nowhere() {
	let (outer, data, sink) = sink();
	for account in ["../evil", "..", "a/b", ""] {
		let error = sink
			.deliver_to_account(account, None, b"x", &[])
			.expect_err(account);
		assert_eq!(
			error.kind(),
			std::io::ErrorKind::InvalidInput,
			"{account:?}"
		);
	}
	assert_eq!(listing(outer.path()), ["data"]);
	assert_eq!(listing(&data), ["accounts"]);
	assert!(listing(&data.join("accounts")).is_empty());
}

#[test]
fn a_traversing_mailbox_name_delivers_nowhere() {
	let (outer, data, sink) = sink();
	for mailbox in ["../x", "..", ".", "a/b", "../../evil"] {
		let error = sink
			.deliver_to_account("alice", Some(mailbox), b"x", &[])
			.expect_err(mailbox);
		assert_eq!(
			error.kind(),
			std::io::ErrorKind::InvalidInput,
			"{mailbox:?}"
		);
	}
	assert_eq!(listing(outer.path()), ["data"]);
	assert_eq!(listing(&data), ["accounts"]);
	assert_eq!(listing(&data.join("accounts")), ["alice"]);
	let folders = listing(&data.join("accounts/alice/folders"));
	assert!(
		folders
			.iter()
			.all(|name| !name.contains('x') || name == "Sent"),
		"no stray folder was created: {folders:?}"
	);
}

#[test]
fn a_named_mailbox_still_receives_mail() {
	let (_outer, data, sink) = sink();
	sink.deliver_to_account("alice", Some("Projects..2024"), b"x", &[])
		.expect("deliver");
	assert_eq!(
		listing(&data.join("accounts/alice/folders/Projects..2024/new")).len(),
		1
	);
}

#[test]
fn the_filter_of_a_traversing_account_is_not_read() {
	let (_outer, data, sink) = sink();
	fs::create_dir_all(data.join("evil")).expect("evil dir");
	fs::write(data.join("evil/filter.sieve"), "keep;").expect("filter");
	let msg = message(&["alice@example.org"]);
	assert!(sink.sieve_outcome("../evil", &msg).is_none());
	fs::create_dir_all(data.join("accounts/alice")).expect("alice dir");
	fs::write(data.join("accounts/alice/filter.sieve"), "keep;").expect("filter");
	assert!(sink.sieve_outcome("alice", &msg).is_some());
}
