//! What `check` says about a submission follows what the server does with
//! the mail its own accounts send.

use std::process::ExitCode;

use super::check_cases::{EXE_AS_PDF, fixture, run};

#[test]
fn a_submission_is_accepted_when_the_server_does_not_inspect_submissions() {
	let (_dir, config, eml) = fixture(
		"[attachments]\nmode = \"quarantine\"\n[antispam]\nscan_authenticated = false\n",
		EXE_AS_PDF.as_bytes(),
	);
	let (result, out) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert!(
		out.ends_with(
			"verdict: quarantine (executable-content, type-mismatch)\n\
			 a submission would be accepted (scan_authenticated = false)\n"
		),
		"{out}"
	);
}

#[test]
fn json_says_accepted_when_the_server_does_not_inspect_submissions() {
	let (_dir, config, eml) = fixture(
		"[attachments]\nmode = \"reject\"\n[antispam]\nscan_authenticated = false\n",
		EXE_AS_PDF.as_bytes(),
	);
	let (_, out) = run(&config, &eml, true);
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(value["verdict"], "reject");
	assert_eq!(value["submission"], "accepted");
}

#[test]
fn a_submission_is_refused_when_the_server_inspects_submissions() {
	let (_dir, config, eml) = fixture(
		"[attachments]\nmode = \"quarantine\"\n[antispam]\nscan_authenticated = true\n",
		EXE_AS_PDF.as_bytes(),
	);
	let (_, out) = run(&config, &eml, false);
	assert!(out.ends_with("a submission would be refused\n"), "{out}");
}
