//! Tests for the suggested finding of the resources check: the limits a new
//! install on this host would get, against what the compose file has.

use super::{Level, evaluate};
use crate::cli::status::test_support::ctx;

fn suggested(limits: &[(&str, &str)], kib: u64) -> (Level, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	let meminfo = dir.path().join("meminfo-fake");
	std::fs::write(&meminfo, format!("MemTotal: {kib} kB\n")).expect("meminfo");
	let services: serde_json::Map<String, serde_json::Value> = limits
		.iter()
		.map(|(name, memory)| {
			(
				(*name).to_string(),
				serde_json::json!({ "mem_limit": memory }),
			)
		})
		.collect();
	let compose = dir.path().join("compose.yaml");
	std::fs::write(
		&compose,
		serde_json::json!({ "services": services }).to_string(),
	)
	.expect("compose");
	let report = evaluate(ctx.config.as_ref().expect("config"), &compose, &meminfo);
	let item = report
		.items
		.iter()
		.find(|item| item.name == "suggested")
		.unwrap_or_else(|| panic!("no suggested finding in {:?}", report.items));
	(item.status, item.detail.clone())
}

const EIGHT_GIB: u64 = 8 * 1024 * 1024;

#[test]
fn an_install_with_the_old_limits_is_told_how_to_adopt_the_new_ones() {
	assert_eq!(
		suggested(
			&[
				("mail", "1g"),
				("db", "1g"),
				("clamav", "3g"),
				("freshclam", "2g")
			],
			EIGHT_GIB
		),
		(
			Level::Warn,
			"a new install on this host (8.0 GiB) would get mail 2g (now 1g), clamav 2g (now \
			 3g), freshclam 1g (now 2g); adopt them with `epistle stack resources set mail \
			 --memory 2g`, `epistle stack resources set clamav --memory 2g` and `epistle stack \
			 resources set freshclam --memory 1g`, then `epistle stack update`"
				.to_string()
		)
	);
}

#[test]
fn limits_that_match_say_so() {
	assert_eq!(
		suggested(
			&[
				("mail", "2g"),
				("db", "1g"),
				("clamav", "2g"),
				("freshclam", "1g")
			],
			EIGHT_GIB
		),
		(
			Level::Ok,
			"the limits are what a new install on this host (8.0 GiB) would get".to_string()
		)
	);
}

#[test]
fn a_mail_limit_above_the_suggestion_is_only_a_suggestion() {
	assert_eq!(
		suggested(
			&[
				("mail", "4g"),
				("db", "1g"),
				("clamav", "2g"),
				("freshclam", "1g")
			],
			EIGHT_GIB
		),
		(
			Level::Ok,
			"a new install on this host (8.0 GiB) would get mail 2g (now 4g); adopt it with \
			 `epistle stack resources set mail --memory 2g`, then `epistle stack update`"
				.to_string()
		)
	);
}

#[test]
fn under_4_gib_a_running_clamav_is_named() {
	assert_eq!(
		suggested(
			&[("mail", "2g"), ("clamav", "3g"), ("freshclam", "2g")],
			3_900_000
		),
		(
			Level::Ok,
			"the limits are what a new install on this host (3.7 GiB) would get; a new \
			 install on this host leaves clamav and freshclam out"
				.to_string()
		)
	);
}
