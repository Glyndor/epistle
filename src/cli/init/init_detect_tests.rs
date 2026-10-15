//! Detection wired into the `--answers` path of `init`.

use super::detect::tests::{MustNotDetect, Scripted, v4};
use super::*;

/// Probes with `detector` and no resolver, so the PTR block reports
/// every lookup as failed without touching the network.
fn no_lookups(detector: &dyn super::detect::Detector) -> Probes<'_> {
	Probes {
		detector,
		resolver: &|| None,
		meminfo: std::path::Path::new("/nonexistent/meminfo"),
	}
}

/// A dry-run answers file under a fresh tempdir, with `extra` appended to
/// the top-level keys.
pub(super) fn dry_run_args(dir: &std::path::Path, extra: &str) -> Args {
	let answers_file = dir.join("answers.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 {extra}\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		dir.join("data").display(),
		dir.join("etc").join("mail.toml").display(),
	);
	std::fs::write(&answers_file, body).expect("write answers");
	Args {
		answers: Some(answers_file),
		dry_run: true,
		print_answers: false,
	}
}

#[test]
fn answers_without_an_address_take_the_detected_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let detector = Scripted::found(Some(v4()), None);
	let mut out = Vec::new();
	let code = run_with(
		dry_run_args(dir.path(), ""),
		&no_lookups(&detector),
		&mut out,
	);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	assert_eq!(detector.calls.get(), 1);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		text.contains("detected public_ipv4 = 8.8.8.8 (not in the answers file)"),
		"the filled address must be reported: {text}"
	);
}

#[test]
fn answers_with_both_addresses_never_call_the_detector() {
	let dir = tempfile::tempdir().expect("tempdir");
	let extra = "public_ipv4 = \"1.1.1.1\"\npublic_ipv6 = \"2606:4700::1111\"\n";
	let mut out = Vec::new();
	let code = run_with(
		dry_run_args(dir.path(), extra),
		&no_lookups(&MustNotDetect),
		&mut out,
	);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		!text.contains("detected"),
		"nothing detected may be reported: {text}"
	);
}

#[test]
fn answers_saying_none_never_call_the_detector() {
	let dir = tempfile::tempdir().expect("tempdir");
	let extra = "public_ipv4 = \"none\"\npublic_ipv6 = \"none\"\n";
	let mut out = Vec::new();
	let code = run_with(
		dry_run_args(dir.path(), extra),
		&no_lookups(&MustNotDetect),
		&mut out,
	);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(
		text,
		"cannot read MemTotal from /nonexistent/meminfo; the containers keep the fixed limits \
		 (mail 1g, db 1g, clamav 3g, freshclam 2g)\n\
		 dry-run: nothing was written\n",
		"no address notice, no hint and no PTR block without an address"
	);
}
