//! What a Sieve filter can do to an account's folders and to its own
//! message, and what the log says when the server has set a limit aside.

use std::path::Path;

use super::*;
use crate::cli::tracing_capture::run_with_capture;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn message(subject: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["alice@example.org".to_string()],
		data: format!("Subject: {subject}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn setup(root: &Path, script: &str) -> LocalDelivery {
	let delivery = LocalDelivery::new(root, directory()).expect("delivery");
	let account = root.join("accounts").join("alice");
	fs::create_dir_all(&account).expect("mkdir");
	fs::write(account.join("filter.sieve"), script).expect("filter");
	delivery
}

fn count(dir: &Path) -> usize {
	fs::read_dir(dir)
		.map(|entries| {
			entries
				.flatten()
				.filter(|e| e.file_name().to_string_lossy().ends_with(".eml"))
				.count()
		})
		.unwrap_or(0)
}

fn inbox(root: &Path) -> usize {
	count(&root.join("accounts/alice/new"))
}

fn folders(root: &Path) -> usize {
	fs::read_dir(root.join("accounts/alice/folders"))
		.map(|entries| entries.flatten().count())
		.unwrap_or(0)
}

const BY_SUBJECT: &str = "require [\"variables\", \"fileinto\"];\n\
	if header :matches \"subject\" \"*\" { fileinto \"${1}\"; }\n";

#[test]
fn a_sender_cannot_make_a_folder_for_every_message() {
	// `fileinto "${1}"` on the Subject makes a folder per distinct subject.
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), BY_SUBJECT);
	let total = io::MAX_AUTO_FOLDERS + 20;
	for n in 0..total {
		delivery
			.deliver_routed(&message(&format!("topic {n}")), None)
			.expect("deliver");
	}
	assert!(
		folders(dir.path()) <= io::MAX_AUTO_FOLDERS,
		"{} folders",
		folders(dir.path())
	);
	// Every message is somewhere: in its folder, or kept when the account
	// was out of room for a new one.
	let filed: usize = fs::read_dir(dir.path().join("accounts/alice/folders"))
		.expect("folders")
		.flatten()
		.map(|folder| count(&folder.path().join("new")))
		.sum();
	assert_eq!(filed + inbox(dir.path()), total);
	assert!(inbox(dir.path()) >= 20, "the overflow is kept in INBOX");
}

#[test]
fn a_subject_that_is_not_a_folder_name_keeps_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), BY_SUBJECT);
	let long = "n".repeat(200);
	for subject in [
		"../escape",
		"..",
		"a/../../b",
		".hidden",
		"mark\u{202e}evil",
		"iso\u{2066}late",
		long.as_str(),
		"",
	] {
		delivery
			.deliver_routed(&message(subject), None)
			.expect("deliver");
	}
	assert_eq!(inbox(dir.path()), 8, "every one of them stays in INBOX");
	// The folders are the ones every account starts with, and nothing was
	// made beside the account.
	let fresh = tempfile::tempdir().expect("tempdir");
	crate::imap::mailbox::ensure_defaults(fresh.path(), "alice").expect("defaults");
	assert_eq!(
		crate::imap::mailbox::list(dir.path(), "alice"),
		crate::imap::mailbox::list(fresh.path(), "alice")
	);
	assert!(!dir.path().join("accounts/escape").exists());
}

#[test]
fn a_redirect_to_something_that_is_not_an_address_keeps_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), "redirect \"Joe <joe@target.example>\";\n");
	let mut delivered = None;
	let events = run_with_capture(|| {
		delivered = Some(
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver"),
		);
	});
	assert!(delivered.expect("delivered").redirects.is_empty());
	assert_eq!(
		inbox(dir.path()),
		1,
		"a failed redirect is a run-time error: keep"
	);
	assert!(
		events.iter().any(|e| e
			.fields
			.get("message")
			.is_some_and(|m| m.contains("redirect"))),
		"{events:?}"
	);
}

#[test]
fn a_redirect_that_works_still_cancels_the_keep() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), "redirect \"joe@target.example\";\n");
	let delivered = delivery
		.deliver_routed(&message("hi"), None)
		.expect("deliver");
	assert_eq!(delivered.redirects.len(), 1);
	assert_eq!(inbox(dir.path()), 0);
}

#[test]
fn redirects_past_the_limit_are_logged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script: String = (0..10)
		.map(|n| format!("redirect :copy \"u{n}@target.example\";\n"))
		.collect();
	let delivery = setup(dir.path(), &script);
	let mut redirects = 0;
	let events = run_with_capture(|| {
		redirects = delivery
			.deliver_routed(&message("hi"), None)
			.expect("deliver")
			.redirects
			.len();
	});
	assert_eq!(redirects, crate::sieve::interp::MAX_REDIRECTS);
	assert!(
		events.iter().any(|e| e
			.fields
			.get("message")
			.is_some_and(|m| m.contains("beyond the limit"))),
		"{events:?}"
	);
}

#[test]
fn a_run_that_overspends_keeps_the_message_and_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = format!("discard;\n{}", "keep;\n".repeat(25_000));
	let delivery = setup(dir.path(), &script);
	let events = run_with_capture(|| {
		delivery
			.deliver_routed(&message("hi"), None)
			.expect("deliver");
	});
	assert_eq!(inbox(dir.path()), 1, "the script's own keep stands");
	assert!(
		events.iter().any(|e| e
			.fields
			.get("message")
			.is_some_and(|m| m.contains("stopped where it was"))),
		"{events:?}"
	);
}

#[test]
fn a_filter_file_over_the_size_limit_is_not_run() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = format!(
		"discard;\n#{}\n",
		"x".repeat(crate::managesieve::store::MAX_SCRIPT_BYTES)
	);
	let delivery = setup(dir.path(), &script);
	let events = run_with_capture(|| {
		delivery
			.deliver_routed(&message("hi"), None)
			.expect("deliver");
	});
	assert_eq!(inbox(dir.path()), 1);
	assert!(
		events.iter().any(|e| e
			.fields
			.get("message")
			.is_some_and(|m| m.contains("size limit"))),
		"{events:?}"
	);
}

#[test]
fn two_names_for_inbox_file_one_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), "fileinto \"INBOX\";\nfileinto \"inbox\";\n");
	delivery
		.deliver_routed(&message("hi"), None)
		.expect("deliver");
	assert_eq!(inbox(dir.path()), 1);
}

/// Every folder the account really has, parents of deep ones included.
fn real_folders(root: &Path) -> usize {
	crate::imap::mailbox::list(root, "alice").len()
}

const DEEP_BY_SUBJECT: &str = "require [\"variables\", \"fileinto\"];\n\
	if header :matches \"subject\" \"*\" { fileinto \"${1}/b/c/d\"; }\n";

#[test]
fn a_deep_name_counts_every_folder_it_makes() {
	// `n/b/c/d` is four folders. Sixty of them would be 240 against a limit
	// of 200 that counted one folder per `fileinto`.
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), DEEP_BY_SUBJECT);
	for n in 0..60 {
		delivery
			.deliver_routed(&message(&format!("p{n}")), None)
			.expect("deliver");
	}
	assert!(
		real_folders(dir.path()) <= io::MAX_AUTO_FOLDERS,
		"{} folders",
		real_folders(dir.path())
	);
	assert!(
		real_folders(dir.path()) > 150,
		"the limit was reached, not stopped short"
	);
	assert!(inbox(dir.path()) > 0, "what did not fit is kept");
}

#[test]
fn a_folder_made_by_a_filter_is_at_most_four_levels_deep() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(
		dir.path(),
		"fileinto \"a/b/c/d\";\nfileinto \"a/b/c/d/e\";\n",
	);
	delivery
		.deliver_routed(&message("hi"), None)
		.expect("deliver");
	let names = crate::imap::mailbox::list(dir.path(), "alice");
	assert!(names.iter().any(|n| n == "a/b/c/d"), "{names:?}");
	assert!(
		!names.iter().any(|n| n.starts_with("a/b/c/d/")),
		"{names:?}"
	);
	assert_eq!(inbox(dir.path()), 1, "the five-level name is kept in INBOX");
}

#[test]
fn deliveries_at_the_same_moment_do_not_pass_the_limit_together() {
	for round in 0..20 {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = std::sync::Arc::new(setup(dir.path(), DEEP_BY_SUBJECT));
		// Room for two more deep names and no more.
		crate::imap::mailbox::ensure_defaults(dir.path(), "alice").expect("defaults");
		for n in 0..(io::MAX_AUTO_FOLDERS - 1 - 5 - 8) {
			crate::imap::mailbox::create(dir.path(), "alice", &format!("pre{n}")).expect("create");
		}
		let handles: Vec<_> = (0..8)
			.map(|t| {
				let delivery = delivery.clone();
				std::thread::spawn(move || {
					delivery
						.deliver_routed(&message(&format!("t{t}")), None)
						.expect("deliver");
				})
			})
			.collect();
		for handle in handles {
			handle.join().expect("join");
		}
		assert!(
			real_folders(dir.path()) <= io::MAX_AUTO_FOLDERS,
			"round {round}: {} folders",
			real_folders(dir.path())
		);
	}
}

#[test]
fn an_overspent_run_keeps_the_discard_and_sends_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = format!(
		"discard;\nredirect \"someone@target.example\";\n{}",
		"noop;\n".repeat(25_000)
	);
	let delivery = setup(dir.path(), &script);
	let mut redirects = 1;
	let events = run_with_capture(|| {
		redirects = delivery
			.deliver_routed(&message("hi"), None)
			.expect("deliver")
			.redirects
			.len();
	});
	assert_eq!(
		inbox(dir.path()),
		0,
		"the discard decided before the run stopped stands"
	);
	assert_eq!(redirects, 0, "an incomplete run never forwards");
	let said = events
		.iter()
		.find(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("stopped where it was"))
		})
		.expect("said");
	assert_eq!(
		said.fields.get("redirects_dropped").map(String::as_str),
		Some("1")
	);
}
