//! `check --strict` exits 3 (refused by policy) for a verdict the server would not deliver
//! as it is; without the flag the exit code is 0 whatever the verdict.

use std::process::ExitCode;

use super::check;
use super::check_cases::{EXE_AS_PDF, fixture};

const CLEAN: &[u8] = b"From: x@example.net\r\nSubject: hi\r\n\r\nhello\r\n";

fn run(mode: &str, message: &[u8], json: bool, strict: bool) -> (ExitCode, String) {
	let (_dir, config, eml) = fixture(&format!("[attachments]\nmode = \"{mode}\"\n"), message);
	let mut out = Vec::new();
	let code =
		check::execute(&config, &eml, json, strict, &mut out).expect("the message is judged");
	(code, String::from_utf8(out).unwrap())
}

#[test]
fn strict_exits_3_for_reject() {
	let (code, out) = run("reject", EXE_AS_PDF.as_bytes(), false, true);
	assert_eq!(code, ExitCode::from(3));
	assert!(out.contains("verdict: reject"), "{out}");
}

#[test]
fn strict_exits_3_for_quarantine() {
	let (code, out) = run("quarantine", EXE_AS_PDF.as_bytes(), false, true);
	assert_eq!(code, ExitCode::from(3));
	assert!(out.contains("verdict: quarantine"), "{out}");
}

#[test]
fn strict_exits_0_for_flag() {
	let (code, out) = run("flag", EXE_AS_PDF.as_bytes(), false, true);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("verdict: flag"), "{out}");
}

#[test]
fn strict_exits_0_for_deliver() {
	let (code, out) = run("quarantine", CLEAN, false, true);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("verdict: deliver"), "{out}");
}

#[test]
fn strict_exits_0_when_the_policy_is_off() {
	let (code, _) = run("off", EXE_AS_PDF.as_bytes(), false, true);
	assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn without_strict_every_verdict_exits_0() {
	for mode in ["flag", "quarantine", "reject"] {
		let (code, _) = run(mode, EXE_AS_PDF.as_bytes(), false, false);
		assert_eq!(code, ExitCode::SUCCESS, "{mode}");
	}
}

#[test]
fn strict_with_json_still_prints_the_object_and_exits_3() {
	let (code, out) = run("reject", EXE_AS_PDF.as_bytes(), true, true);
	assert_eq!(code, ExitCode::from(3));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(value["verdict"], "reject");
}

/// The help of `--strict` names the code the command really exits with.
#[test]
fn the_help_of_strict_names_exit_3() {
	use clap::CommandFactory;

	let mut cli = crate::cli::Cli::command();
	let check = cli
		.find_subcommand_mut("attachments")
		.and_then(|a| a.find_subcommand_mut("check"))
		.expect("attachments check exists");
	let help = check.render_long_help().to_string();
	assert!(help.contains("Exit with 3 when the verdict"), "{help}");
}
