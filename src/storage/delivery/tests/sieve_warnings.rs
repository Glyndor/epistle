//! What the log says when a Sieve filter ran out, was cut short or could not
//! be run, and how often it says it: once an hour per account. Plus the flags
//! and the lock file a filter touches.

use super::sieve_limits::{count, inbox, message, setup};
use super::*;
use crate::cli::trace::capture::run_with_capture;

#[test]
fn the_overspending_warning_is_said_once_an_hour_for_an_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = format!("discard;\n{}", "noop;\n".repeat(25_000));
	let delivery = setup(dir.path(), &script);
	let events = run_with_capture(|| {
		for _ in 0..5 {
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver");
		}
	});
	let said = events
		.iter()
		.filter(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("stopped where it was"))
		})
		.count();
	assert_eq!(said, 1, "five messages, one line");
}

#[test]
fn a_body_past_the_window_is_counted_and_said_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = "require \"body\";\nif body :contains \"spamword\" { discard; }\n";
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = setup(dir.path(), script).with_metrics(metrics.clone());
	let mut big = message("hi");
	big.data.extend(std::iter::repeat_n(b'x', (1 << 20) + 10));
	big.data.extend_from_slice(b" spamword\r\n");
	let events = run_with_capture(|| {
		for _ in 0..3 {
			delivery.deliver_routed(&big, None).expect("deliver");
		}
	});
	assert_eq!(inbox(dir.path()), 3, "the word is past what the test reads");
	assert_eq!(
		metrics.snapshot().get("sieve_inspection_truncated"),
		Some(&3)
	);
	let said = events
		.iter()
		.filter(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("looked at part of a message only"))
		})
		.count();
	assert_eq!(said, 1);
}

#[test]
fn an_old_long_key_is_a_false_test_and_a_line_in_the_log_once_an_hour() {
	let dir = tempfile::tempdir().expect("tempdir");
	let long = "a".repeat(300);
	let script = format!(
		"require \"fileinto\";\nif header :matches \"subject\" \"{long}\" {{ discard; }}\nfileinto \"After\";\n"
	);
	let delivery = setup(dir.path(), &script);
	let events = run_with_capture(|| {
		for _ in 0..3 {
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver");
		}
	});
	assert_eq!(
		count(&dir.path().join("accounts/alice/folders/After/new")),
		3,
		"the rest of the script ran every time"
	);
	let said = events
		.iter()
		.filter(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("over the length or wildcard limit"))
		})
		.count();
	assert_eq!(said, 1);
}

#[test]
fn the_flags_sidecar_holds_no_more_than_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = Uuid::new_v4();
	let tokens: Vec<String> = (0..500).map(|n| format!("k{n}")).collect();
	io::write_flag_sidecar(dir.path(), id, &tokens);
	let path = crate::util::path_component::message_file(
		dir.path(),
		id,
		crate::util::path_component::MessageExt::Flags,
	)
	.expect("path");
	let written: Vec<serde_json::Value> =
		serde_json::from_slice(&fs::read(path).expect("read")).expect("json");
	assert_eq!(written.len(), crate::sieve::interp::MAX_FLAGS);
}

fn said(events: &[crate::cli::trace::capture::CapturedEvent], text: &str) -> usize {
	events
		.iter()
		.filter(|e| e.fields.get("message").is_some_and(|m| m.contains(text)))
		.count()
}

#[test]
fn the_folder_lock_is_private() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(
		dir.path(),
		"require \"fileinto\";\nfileinto :create \"Lists\";\n",
	);
	delivery
		.deliver_routed(&message("hi"), None)
		.expect("deliver");
	let mode = fs::metadata(dir.path().join("accounts/alice/.folders.lock"))
		.expect("lock file")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, "{mode:o}");
}

#[test]
fn a_filter_that_does_not_parse_is_said_once_an_hour_and_the_mail_is_kept() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(dir.path(), "if if if { ;; \"unterminated\n");
	let events = run_with_capture(|| {
		for _ in 0..3 {
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver");
		}
	});
	assert_eq!(inbox(dir.path()), 3);
	assert_eq!(said(&events, "could not be read as a Sieve script"), 1);
}

#[test]
fn files_into_more_folders_than_the_limit_are_counted_and_said_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut script = String::from("require \"fileinto\";\n");
	for n in 0..12 {
		script.push_str(&format!("fileinto :copy \"F{n}\";\n"));
	}
	let delivery = setup(dir.path(), &script);
	let events = run_with_capture(|| {
		for _ in 0..3 {
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver");
		}
	});
	assert_eq!(said(&events, "beyond the limit of folders"), 1);
	let made = (0..12)
		.filter(|n| {
			dir.path()
				.join(format!("accounts/alice/folders/F{n}"))
				.exists()
		})
		.count();
	assert_eq!(made, 8, "eight folders, not twelve");
}

#[test]
fn the_other_delivery_warnings_are_said_once_an_hour_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = setup(
		dir.path(),
		"redirect \"not an address\";\nredirect :copy \"also not\";\n",
	);
	let events = run_with_capture(|| {
		for _ in 0..4 {
			delivery
				.deliver_routed(&message("hi"), None)
				.expect("deliver");
		}
	});
	assert_eq!(said(&events, "not an address"), 1, "{events:?}");
}
