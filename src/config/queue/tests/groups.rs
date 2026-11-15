//! `[queue] per_group_concurrency`: the limit of each receiver group.

use super::base::with_queue;
use super::*;
use crate::queue::limits::GroupLimit;
use crate::queue::warmup::Group;

#[test]
fn a_group_limit_parses_in_both_forms() {
	let config = with_queue(
		"concurrency = 8\n[queue.per_group_concurrency]\ngmail = 2\n\
		 outlook = { concurrency = 2, min_wait_secs = 30 }\n\
		 gmx = { concurrency = 1 }",
	);
	config.validate_queue_limits().expect("valid");
	let limits = &config.queue.per_group_concurrency;
	assert_eq!(limits.len(), 3);
	assert_eq!(limits[&Group::Gmail], GroupLimit::new(2));
	assert_eq!(limits[&Group::Gmail].min_wait_secs, 0);
	assert_eq!(
		limits[&Group::Outlook],
		GroupLimit {
			concurrency: 2,
			min_wait_secs: 30
		}
	);
	assert_eq!(limits[&Group::Gmx], GroupLimit::new(1));
}

#[test]
fn an_unknown_group_is_refused() {
	let error = toml::from_str::<crate::config::Config>(
		"hostname = \"mail.example.org\"\ndata_dir = \"/d\"\n\
		 [queue.per_group_concurrency]\npostfix = 2\n",
	)
	.expect_err("an unknown group");
	let message = error.to_string();
	assert!(message.contains("postfix"), "{message}");
	for known in ["gmail", "outlook", "yahoo", "icloud", "gmx", "mailru"] {
		assert!(message.contains(known), "{known} in {message}");
	}
}

#[test]
fn a_group_limit_of_the_wrong_shape_is_refused() {
	for section in [
		"gmail = -1",
		"gmail = \"two\"",
		"gmail = { min_wait_secs = 5 }",
		"gmail = { concurrency = 1, wait = 5 }",
	] {
		let parsed = toml::from_str::<crate::config::Config>(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/d\"\n\
			 [queue.per_group_concurrency]\n{section}\n"
		));
		assert!(parsed.is_err(), "{section}");
	}
}

#[test]
fn a_group_limit_out_of_range_is_refused() {
	for (section, message) in [
		(
			"gmail = 0",
			"[queue] per_group_concurrency.gmail concurrency must be between 1 and concurrency (8) (got 0)",
		),
		(
			"gmail = 9",
			"[queue] per_group_concurrency.gmail concurrency must be between 1 and concurrency (8) (got 9)",
		),
		("outlook = { concurrency = 5 }", ""),
		(
			"yahoo = { concurrency = 2, min_wait_secs = 3601 }",
			"[queue] per_group_concurrency.yahoo min_wait_secs must be between 0 and 3600 seconds (got 3601)",
		),
	] {
		let result = with_queue(&format!(
			"concurrency = 8\n[queue.per_group_concurrency]\n{section}"
		))
		.validate_queue_limits();
		if message.is_empty() {
			result.expect("a limit inside the range");
			continue;
		}
		assert_eq!(
			result.expect_err(section).to_string(),
			format!("invalid configuration: {message}")
		);
	}
	let exact = with_queue(
		"concurrency = 8\n[queue.per_group_concurrency]\n\
		 gmail = { concurrency = 8, min_wait_secs = 3600 }",
	);
	exact.validate_queue_limits().expect("both bounds allowed");
}

#[test]
fn the_other_group_cannot_be_limited() {
	let error = with_queue("[queue.per_group_concurrency]\nother = 2")
		.validate_queue_limits()
		.expect_err("other is every unrelated receiver");
	assert!(
		error.to_string().contains("cannot limit `other`"),
		"{error}"
	);
}

#[test]
fn the_group_table_is_absent_by_default() {
	assert!(Queue::default().per_group_concurrency.is_empty());
	let parsed: Queue = toml::from_str("concurrency = 4").expect("parse");
	assert!(parsed.per_group_concurrency.is_empty());
	let config = with_queue("concurrency = 4");
	assert!(config.queue.per_group_concurrency.is_empty());
	config.validate_queue_limits().expect("valid");
}
