//! `podup audit` on the compose file `epistle init` writes, for a stack with
//! every service. podup 6.0.0 runs 24 hardening checks over a compose file.
//! Each finding the generated file has is either fixed or accepted here with
//! the reason it is accepted, so a new finding fails the test and an
//! accepted one that stops appearing fails it too: the list stays true.
//!
//! The test needs a podup binary. When none that is 6.0.0 or newer is on the
//! path (or at `EPISTLE_PODUP`) it says so and stops, unless
//! `EPISTLE_REQUIRE_PODUP` is set, which the CI job that installs podup sets:
//! there a missing podup is a failure and not a skipped test.

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};

use serde_json::Value;

use super::*;

/// The accepted findings: `(check, service, why it holds)`.
const ACCEPTED: &[(&str, &str, &str)] = &[
	(
		"port_published_on_all_interfaces",
		"mail",
		"the listeners are the mail server; `epistle stack ports` narrows one, and the warning about a port nobody chose is kept by `port_warnings`",
	),
	(
		"no_init",
		"mail",
		"PID 1 is `epistle serve`, which handles SIGTERM itself and drains for its stop grace period",
	),
	(
		"no_init",
		"db",
		"PID 1 is postgres, which reaps its own children and handles SIGTERM",
	),
	(
		"no_init",
		"clamav",
		"the entrypoint ends in `exec clamd`, so PID 1 is clamd",
	),
	(
		"no_init",
		"freshclam",
		"the entrypoint ends in `exec freshclam`, so PID 1 is freshclam",
	),
	(
		"no_userns",
		"db",
		"deliberate in `services.rs`: the volumes an earlier start initialised are owned by uid 999 under the default mapping",
	),
	(
		"no_userns",
		"clamav",
		"not changed here: `auto` needs subordinate ids and changes who owns the files of the existing signature volume",
	),
	("no_userns", "freshclam", "same volume as clamav"),
	(
		"no_cpu_limit",
		"mail",
		"a mail server takes the cores it needs; memory and pids are what is limited (`epistle stack resources`)",
	),
	("no_cpu_limit", "db", "same as the mail service"),
	(
		"no_cpu_limit",
		"clamav",
		"a scan has to finish inside the SMTP session",
	),
	(
		"no_cpu_limit",
		"freshclam",
		"not limited; memory and pids are",
	),
	(
		"swap_unbounded",
		"mail",
		"waiting for a decision on `memswap_limit`: bounding swap turns a slow stack into an OOM kill",
	),
	("swap_unbounded", "db", "same as the mail service"),
	("swap_unbounded", "clamav", "same as the mail service"),
	("swap_unbounded", "freshclam", "same as the mail service"),
	(
		"no_cpu_limit",
		"certs",
		"a certificate renewal is short and rare, and memory and pids are limited",
	),
	("no_cpu_limit", "panel", "not limited; memory and pids are"),
	(
		"no_init",
		"certs",
		"PID 1 is the certificates process, which handles SIGTERM itself",
	),
	(
		"no_init",
		"panel",
		"PID 1 is the panel runtime, which handles SIGTERM itself",
	),
	("swap_unbounded", "certs", "same as the mail service"),
	("swap_unbounded", "panel", "same as the mail service"),
	(
		"host_namespace",
		"panel",
		"deliberate: the panel joins the mail container's network namespace to reach the API on its loopback (`services/panel.rs`)",
	),
	(
		"sensitive_bind_mount",
		"mail",
		"the configuration directory is mounted read-only at the same path on both sides, so `serve` and the host commands read one mail.toml",
	),
	(
		"sensitive_bind_mount",
		"certs",
		"same as the mail service: the configuration directory, read-only",
	),
	(
		"no_health_action",
		"db",
		"a restart in the middle of a crash recovery only starts it over; see `services.rs`",
	),
];

/// A podup of the version the generated file is written for, if there is one.
fn podup() -> Option<std::path::PathBuf> {
	let program = std::env::var_os("EPISTLE_PODUP").unwrap_or_else(|| "podup".into());
	let out = Command::new(&program).arg("--version").output().ok()?;
	let text = String::from_utf8_lossy(&out.stdout);
	let version = text
		.split("podup version v")
		.nth(1)?
		.split_whitespace()
		.next()?;
	let numbers: Vec<u64> = version
		.split('.')
		.filter_map(|part| part.parse().ok())
		.collect();
	(numbers.as_slice() >= [6, 0, 0].as_slice()).then(|| program.into())
}

/// The generated file of a stack that runs every service.
fn full_stack() -> Value {
	let mut answers = stack_answers();
	answers.services.api = true;
	answers.services.certs = true;
	answers.services.antivirus = Some(true);
	answers.services.panel_image = Some("ghcr.io/glyndor/epistle-panel:0.3.1".to_string());
	render(&answers, true)
}

fn findings(podup: &std::path::Path, compose: &Value) -> BTreeMap<(String, String), String> {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("compose.yaml");
	std::fs::write(&file, serde_json::to_vec_pretty(compose).expect("json")).expect("write");
	let out = Command::new(podup)
		.arg("-f")
		.arg(&file)
		.args(["audit", "--format", "json"])
		.stdin(Stdio::null())
		.output()
		.expect("run podup audit");
	assert!(
		out.status.success(),
		"podup audit failed: {}",
		String::from_utf8_lossy(&out.stderr)
	);
	let report: Value = serde_json::from_slice(&out.stdout).expect("audit prints JSON");
	report["findings"]
		.as_array()
		.expect("findings array")
		.iter()
		.map(|finding| {
			(
				finding["check"].as_str().expect("check").to_string(),
				finding["service"].as_str().expect("service").to_string(),
			)
		})
		.zip(
			report["findings"]
				.as_array()
				.expect("findings array")
				.iter(),
		)
		.map(|(key, finding)| {
			(
				key,
				finding["reason"].as_str().unwrap_or_default().to_string(),
			)
		})
		.collect()
}

#[test]
fn the_generated_stack_has_only_the_findings_accepted_here() {
	let Some(podup) = podup() else {
		assert!(
			std::env::var_os("EPISTLE_REQUIRE_PODUP").is_none(),
			"EPISTLE_REQUIRE_PODUP is set but there is no podup 6.0.0 or newer"
		);
		eprintln!(
			"no podup 6.0.0 or newer on the path; the audit of the generated stack did not run"
		);
		return;
	};
	let found = findings(&podup, &full_stack());
	let accepted: BTreeSet<(String, String)> = ACCEPTED
		.iter()
		.map(|(check, service, _)| ((*check).to_string(), (*service).to_string()))
		.collect();
	let seen: BTreeSet<(String, String)> = found.keys().cloned().collect();
	let new: Vec<_> = seen
		.difference(&accepted)
		.map(|key| (key, &found[key]))
		.collect();
	let stale: Vec<_> = accepted.difference(&seen).collect();
	assert!(
		new.is_empty(),
		"podup audit reports findings the stack does not accept: {new:?}; fix the generated file or accept them in ACCEPTED with the reason"
	);
	assert!(
		stale.is_empty(),
		"ACCEPTED lists findings podup no longer reports: {stale:?}; remove them"
	);
}

#[test]
fn every_accepted_finding_says_why() {
	for (check, service, why) in ACCEPTED {
		assert!(
			why.split_whitespace().count() >= 4,
			"{check} on {service} is accepted without a reason"
		);
	}
	let unique: BTreeSet<_> = ACCEPTED.iter().map(|(c, s, _)| (c, s)).collect();
	assert_eq!(unique.len(), ACCEPTED.len(), "a finding is listed twice");
}
