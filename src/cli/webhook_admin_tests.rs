use std::path::PathBuf;
use std::time::Duration;

use clap::{CommandFactory, Parser};

use super::*;
use crate::cli::resource::{Run, test_config};

pub(super) const HOOK: &str = "
# events
[webhook] # endpoint
url = 'https://hooks.example/mail' # where
secret = 'hook-secret'
";

pub(super) fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

pub(super) fn run_with(extra: &str, args: &[&str], stdin: &str, dry_run: bool) -> Run {
	let (_dir, file) = test_config(extra);
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut full = vec!["epistle", "webhook"];
	full.extend_from_slice(args);
	let crate::cli::Command::Webhook { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("webhook arguments must select the webhook command")
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		file.path(),
		action,
		dry_run,
		false,
		&mut std::io::BufReader::new(stdin.as_bytes()),
		&mut out,
		&mut status,
		no_restart,
	);
	Run {
		result,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		after: std::fs::read_to_string(file.path()).unwrap(),
		before,
	}
}

pub(super) fn run(extra: &str, args: &[&str]) -> Run {
	run_with(extra, args, "", false)
}

#[test]
fn webhook_accepts_config_before_or_after_the_action_and_defaults_it() {
	for (args, want) in [
		(vec!["epistle", "webhook", "show"], "/etc/epistle/mail.toml"),
		(
			vec!["epistle", "webhook", "--config", "/tmp/x.toml", "show"],
			"/tmp/x.toml",
		),
		(
			vec!["epistle", "webhook", "show", "--config", "/tmp/x.toml"],
			"/tmp/x.toml",
		),
	] {
		let matches = crate::cli::Cli::command()
			.try_get_matches_from(args)
			.unwrap();
		assert_eq!(
			matches
				.subcommand_matches("webhook")
				.unwrap()
				.get_one::<PathBuf>("config")
				.unwrap(),
			&PathBuf::from(want)
		);
	}
}

#[test]
fn show_masks_the_secret_and_reports_an_absent_webhook() {
	let run = run(HOOK, &["show"]);
	assert_eq!(
		run.out,
		"url\thttps://hooks.example/mail\nsecret\tset\nenabled\tyes\n"
	);
	assert!(!run.out.contains("hook-secret"));
	assert_eq!(
		super::tests::run(HOOK, &["show", "--json"]).out,
		"{\"enabled\":true,\"secret\":\"set\",\"url\":\"https://hooks.example/mail\"}\n"
	);
	assert_eq!(super::tests::run("", &["show"]).out, "url\tunset\n");
	assert_eq!(super::tests::run("", &["show", "--json"]).out, "null\n");
}

/// A one-shot HTTP server: answers every request with `status` and records
/// the request head and body.
fn serve(status: u16) -> (String, std::thread::JoinHandle<String>) {
	use std::io::{Read, Write};
	let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let url = format!("http://{}/hook", listener.local_addr().unwrap());
	let handle = std::thread::spawn(move || {
		let (mut stream, _) = listener.accept().unwrap();
		let mut request = Vec::new();
		let mut buffer = [0u8; 4096];
		loop {
			let read = stream.read(&mut buffer).unwrap();
			request.extend_from_slice(&buffer[..read]);
			let text = String::from_utf8_lossy(&request);
			if let Some((head, body)) = text.split_once("\r\n\r\n") {
				let length = head
					.lines()
					.find_map(|l| {
						l.to_ascii_lowercase()
							.strip_prefix("content-length: ")
							.map(str::to_string)
					})
					.and_then(|v| v.trim().parse::<usize>().ok())
					.unwrap_or(0);
				if body.len() >= length {
					break;
				}
			}
		}
		write!(
			stream,
			"HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
		)
		.unwrap();
		String::from_utf8_lossy(&request).to_string()
	});
	(url, handle)
}

fn config_for(url: &str) -> (tempfile::TempDir, tempfile::NamedTempFile, Config) {
	let (dir, file) = test_config(&format!(
		"\n[webhook]\nurl = '{url}'\nsecret = 'hook-secret'\n"
	));
	let config = Config::load(file.path()).unwrap();
	(dir, file, config)
}

#[test]
fn test_posts_one_signed_test_event_and_reports_the_status() {
	let (url, server) = serve(204);
	let (_dir, _file, config) = config_for(&url);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let code = probe::run_within(&config, Duration::from_secs(5), &mut out, &mut status).unwrap();
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(String::from_utf8(out).unwrap(), "ok\tHTTP 204\n");
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"webhook test passed; a `test` event was delivered\n"
	);
	let request = server.join().unwrap();
	assert!(
		request.ends_with(
			"{\"event\":\"test\",\"message\":\"epistle webhook test: connectivity check, no mail activity\"}"
		),
		"the body must be exactly the documented test event: {request}"
	);
	assert!(
		request
			.to_ascii_lowercase()
			.contains("x-webhook-signature: sha256="),
		"the test event must be signed: {request}"
	);
}

#[test]
fn test_fails_on_an_error_status_an_unreachable_endpoint_and_silence() {
	let (url, server) = serve(500);
	let (_dir, _file, config) = config_for(&url);
	let error = probe::run_within(
		&config,
		Duration::from_secs(5),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	server.join().unwrap();
	assert_eq!(error, "webhook test failed: the endpoint answered HTTP 500");
	let (_dir, _file, config) = config_for("http://127.0.0.1:1/hook");
	let error = probe::run_within(
		&config,
		Duration::from_secs(5),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert!(
		error.as_ref().starts_with("webhook test failed: "),
		"{error}"
	);
	let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let (_dir, _file, config) =
		config_for(&format!("http://{}/hook", listener.local_addr().unwrap()));
	let started = std::time::Instant::now();
	let error = probe::run_within(
		&config,
		Duration::from_millis(300),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert_eq!(error, "webhook test failed: no answer within 0.3 s");
	assert!(
		started.elapsed() < Duration::from_secs(5),
		"the limit must cut a silent endpoint"
	);
}

#[test]
fn test_names_the_missing_webhook() {
	let run = run("", &["test"]);
	assert_eq!(
		run.result.unwrap_err(),
		"no webhook is configured; run `epistle webhook set` first"
	);
}
