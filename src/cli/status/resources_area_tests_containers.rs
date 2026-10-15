//! Tests for the containers finding of the resources check: the sum of the
//! compose memory limits against a fake `/proc/meminfo`.

use super::{Level, evaluate};
use crate::cli::status::CheckArea;
use crate::cli::status::report::render_json;
use crate::cli::status::test_support::ctx;

/// A `/proc/meminfo` whose `MemTotal` is `kib` KiB.
fn meminfo(dir: &std::path::Path, kib: u64) -> std::path::PathBuf {
	let path = dir.join("meminfo-fake");
	std::fs::write(
		&path,
		format!("MemTotal:       {kib} kB\nMemFree:         1000 kB\n"),
	)
	.expect("meminfo");
	path
}

/// A compose file whose services may use `limits`.
fn compose(dir: &std::path::Path, limits: &[(&str, &str)]) -> std::path::PathBuf {
	let services: serde_json::Map<String, serde_json::Value> = limits
		.iter()
		.map(|(name, memory)| {
			(
				(*name).to_string(),
				serde_json::json!({ "mem_limit": memory }),
			)
		})
		.collect();
	let path = dir.join("compose.yaml");
	std::fs::write(
		&path,
		serde_json::json!({ "services": services }).to_string(),
	)
	.expect("compose");
	path
}

const TODAY: [(&str, &str); 4] = [
	("mail", "1g"),
	("db", "1g"),
	("clamav", "3g"),
	("freshclam", "2g"),
];

fn containers(limits: &[(&str, &str)], kib: Option<u64>) -> (Level, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	let meminfo = match kib {
		Some(kib) => meminfo(dir.path(), kib),
		None => dir.path().join("no-meminfo"),
	};
	let report = evaluate(
		ctx.config.as_ref().expect("config"),
		&compose(dir.path(), limits),
		&meminfo,
	);
	let item = &report.items[0];
	assert_eq!(item.name, "containers");
	(item.status, item.detail.clone())
}

#[test]
fn limits_over_85_percent_of_the_host_warn_and_name_the_largest() {
	assert_eq!(
		containers(&TODAY, Some(8 * 1024 * 1024)),
		(
			Level::Warn,
			"the containers may use 7.0 GiB of the host's 8.0 GiB (87%), more than 85%; \
			 the largest are clamav (3g) and freshclam (2g); lower one with \
			 `epistle stack resources set clamav --memory 2816m`"
				.to_string()
		)
	);
}

#[test]
fn limits_within_85_percent_are_fine() {
	assert_eq!(
		containers(
			&[
				("mail", "2g"),
				("db", "1g"),
				("clamav", "2g"),
				("freshclam", "1g")
			],
			Some(8 * 1024 * 1024)
		),
		(
			Level::Ok,
			"the containers may use 6.0 GiB of the host's 8.0 GiB (75%)".to_string()
		)
	);
	assert_eq!(
		containers(&TODAY, Some(16 * 1024 * 1024)).0,
		Level::Ok,
		"7 GiB of 16 GiB"
	);
}

#[test]
fn exactly_85_percent_does_not_warn() {
	// 17 GiB of 20 GiB is 85%.
	assert_eq!(
		containers(&[("mail", "17g")], Some(20 * 1024 * 1024)).0,
		Level::Ok
	);
	assert_eq!(
		containers(&[("mail", "17409m")], Some(20 * 1024 * 1024)).0,
		Level::Warn
	);
}

#[test]
fn an_unreadable_meminfo_warns() {
	let (level, detail) = containers(&TODAY, None);
	assert_eq!(level, Level::Warn);
	assert!(
		detail.starts_with("cannot read MemTotal from ") && detail.ends_with("no-meminfo"),
		"{detail}"
	);
}

#[test]
fn status_json_carries_both_findings() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	let report = evaluate(
		ctx.config.as_ref().expect("config"),
		&compose(dir.path(), &TODAY),
		&meminfo(dir.path(), 8 * 1024 * 1024),
	);
	let mut out = Vec::new();
	render_json(&[(CheckArea::Resources, report)], &mut out).expect("json");
	let printed: serde_json::Value = serde_json::from_slice(&out).expect("parse");
	let warning = "the containers may use 7.0 GiB of the host's 8.0 GiB (87%), more than 85%; \
	               the largest are clamav (3g) and freshclam (2g); lower one with \
	               `epistle stack resources set clamav --memory 2816m`";
	let suggestion = "a new install on this host (8.0 GiB) would get mail 2g (now 1g), clamav \
	                  2g (now 3g), freshclam 1g (now 2g); adopt them with `epistle stack \
	                  resources set mail --memory 2g`, `epistle stack resources set clamav \
	                  --memory 2g` and `epistle stack resources set freshclam --memory 1g`, then \
	                  `epistle stack update`";
	assert_eq!(
		printed,
		serde_json::json!({
			"resources": {
				"status": "warn",
				"detail": format!("{warning}; {suggestion}"),
				"items": [
					{"name": "containers", "status": "warn", "detail": warning},
					{"name": "suggested", "status": "warn", "detail": suggestion},
					{
						"name": "message budget",
						"status": "ok",
						"detail": "204 MiB, derived from the 1024 MiB the mail container may use \
								   (mem_limit in compose.yaml)"
					},
				],
			}
		})
	);
}

#[test]
fn control_characters_in_service_names_are_not_echoed() {
	let (level, detail) = containers(
		&[("evil\u{1b}]0;x\u{7}", "7g"), ("mail", "7g")],
		Some(8 * 1024 * 1024),
	);
	assert_eq!(level, Level::Warn);
	assert!(detail.contains("the largest are evil"), "{detail}");
	assert!(
		!detail.chars().any(|c| c == '\u{1b}' || c == '\u{7}'),
		"{:?}",
		detail.escape_debug().to_string()
	);
}
