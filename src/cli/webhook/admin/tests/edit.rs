use crate::cli::webhook::admin::tests::base::{HOOK, run, run_with};
use crate::cli::webhook::admin::tests::*;

#[test]
fn set_creates_the_section_with_the_secret_from_stdin() {
	let run = run_with(
		"",
		&["set", "https://hooks.example/mail", "--secret-stdin"],
		"s3cret-value\r\n",
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		format!(
			"{}\n[webhook]\nurl = \"https://hooks.example/mail\"\nsecret = \"s3cret-value\"\n",
			run.before
		)
	);
	assert_eq!(run.status, "webhook saved\nThe server must be restarted.\n");
	assert!(
		!run.out.contains("s3cret-value") && !run.status.contains("s3cret-value"),
		"the secret must never be echoed"
	);
}

#[test]
fn set_changes_the_url_in_place_and_keeps_the_existing_secret() {
	let run = run(HOOK, &["set", "https://other.example/hook"]);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace(
			"url = 'https://hooks.example/mail' # where",
			"url = \"https://other.example/hook\" # where"
		),
		"only the URL may change when no new secret is given"
	);
}

#[test]
fn set_replaces_the_secret_when_one_is_piped_in() {
	let run = run_with(
		HOOK,
		&["set", "https://hooks.example/mail", "--secret-stdin"],
		"new-secret\n",
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before
			.replace("secret = 'hook-secret'", "secret = \"new-secret\"")
	);
}

#[test]
fn loopback_http_is_accepted() {
	for url in [
		"http://127.0.0.1:9000/h",
		"http://localhost/h",
		"http://[::1]:9000/h",
	] {
		let run = run("", &["set", url]);
		assert_eq!(run.result.unwrap(), ExitCode::SUCCESS, "{url}");
	}
}

#[test]
fn unset_removes_the_section_and_keeps_its_comments() {
	let run = run(HOOK, &["unset"]);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace(
			"\n# events\n[webhook] # endpoint\nurl = 'https://hooks.example/mail' # where\nsecret = 'hook-secret'\n",
			""
		) + "# events\n# endpoint\n# where\n"
	);
}

#[test]
fn unset_is_refused_while_an_alert_posts_to_it() {
	let alert = "\n[[alerts]]\nname = 'storm'\nmetric = 'bounced'\nop = '>='\nthreshold = 5\nwindow_secs = 60\ncooldown_secs = 60\nwebhook = true\n";
	let run = run(&format!("{HOOK}{alert}"), &["unset"]);
	assert_eq!(
		run.result.unwrap_err(),
		"alert \"storm\" posts to the webhook; remove it or turn its webhook off first"
	);
	assert!(run.after == run.before);
}

#[test]
fn dry_run_prints_the_diff_and_writes_nothing() {
	let run = run_with(HOOK, &["unset"], "", true);
	assert!(
		run.out.contains("-url = 'https://hooks.example/mail'"),
		"{}",
		run.out
	);
	assert_eq!(run.after, run.before);
	assert!(run.status.is_empty());
}

#[test]
fn invalid_requests_are_refused_and_leave_the_file_untouched() {
	for (args, stdin, message) in [
		(
			vec!["set", "http://hooks.example/mail"],
			"",
			"the URL must be https (or a loopback http endpoint)",
		),
		(
			vec!["set", "http://localhost.example.net/h"],
			"",
			"the URL must be https (or a loopback http endpoint)",
		),
		(
			vec!["set", "http://127.0.0.1.example.net/h"],
			"",
			"the URL must be https (or a loopback http endpoint)",
		),
		(
			vec!["set", "http://192.0.2.1/h"],
			"",
			"the URL must be https (or a loopback http endpoint)",
		),
		(
			vec!["set", "ftp://hooks.example/mail"],
			"",
			"the URL must be https (or a loopback http endpoint)",
		),
		(
			vec!["set", "https://user:pw@hooks.example/mail"],
			"",
			"the URL must not contain credentials: sign requests with --secret-stdin instead",
		),
		(
			vec!["set", "not a url"],
			"",
			"\"not a url\" is not a valid URL",
		),
		(
			vec!["set", "https://hooks.example/mail", "--secret-stdin"],
			"",
			"no webhook secret on stdin: pipe it in as one line",
		),
		(
			vec!["set", "https://hooks.example/mail", "--secret-stdin"],
			"a${HOME}b\n",
			"the webhook secret contains \"${\", which the configuration loader would expand as an environment reference",
		),
	] {
		let run = run_with(HOOK, &args, stdin, false);
		assert_eq!(run.result.unwrap_err(), message, "{args:?}");
		assert!(run.after == run.before, "{args:?} must not change the file");
	}
}
