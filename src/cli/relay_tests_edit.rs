use super::tests::{RULES, no_restart, parse};
use super::*;
use crate::cli::resource::test_config;

struct Run {
	result: Result<ExitCode, super::super::resource::ResourceError>,
	out: String,
	status: String,
	after: String,
	before: String,
}

fn run(args: &[&str], stdin: &str, dry_run: bool) -> Run {
	let (_dir, file) = test_config(RULES);
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let result = execute_with(
		file.path(),
		parse(args),
		dry_run,
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

#[test]
fn add_writes_a_new_domain_relay_with_auth_from_stdin() {
	let run = run(
		&[
			"add",
			"--domain",
			"Example.NET",
			"--host",
			"relay.example.net",
			"--starttls",
			"--username",
			"mailer",
			"--password-stdin",
			"--socks-proxy",
			"127.0.0.1:1080",
		],
		"s3cret-pass\r\n",
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		format!(
			"{}\n[[transport]]\ndomain = \"example.net\"\nkind = \"relay\"\nhost = \"relay.example.net\"\nport = 587\nstarttls = true\nusername = \"mailer\"\npassword = \"s3cret-pass\"\nsocks_proxy = \"127.0.0.1:1080\"\n",
			run.before
		),
		"the new rule must be appended with a lowercase domain, the STARTTLS default port and the stored password"
	);
	assert_eq!(run.status, "relay saved\nThe server must be restarted.\n");
	assert!(
		!run.out.contains("s3cret-pass") && !run.status.contains("s3cret-pass"),
		"the password must never be echoed"
	);
}

#[test]
fn add_updates_the_default_route_in_place_and_keeps_its_comments() {
	let run = run(
		&[
			"add",
			"--host",
			"other.example.net",
			"--port",
			"2525",
			"--starttls",
			"--username",
			"u",
		],
		"",
		false,
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before
			.replace("host = 'smtp.example.net'", "host = \"other.example.net\"")
			.replace("port  =  587 # submission", "port  =  2525 # submission"),
		"only the changed values may differ; the stored password is reused when the user is unchanged"
	);
}

#[test]
fn add_without_auth_drops_stale_credentials() {
	let run = run(&["add", "--host", "smtp.example.net"], "", false);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before
			.replace("port  =  587 # submission", "port  =  25 # submission")
			.replace("starttls = true\n", "")
			.replace("username = 'u' # who\npassword = 'p-secret'\n", "")
			+ "# who\n",
		"plain relay must clear starttls and the credentials but keep their comments"
	);
}

#[test]
fn remove_deletes_only_the_relay_rule_and_keeps_its_comments() {
	let run = run(&["remove"], "", false);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace(
			"\n# default route\n[[transport]] # catch-all\nkind = 'relay'\nhost = 'smtp.example.net'\nport  =  587 # submission\nstarttls = true\nusername = 'u' # who\npassword = 'p-secret'\n",
			""
		) + "# default route\n# catch-all\n# submission\n# who\n"
	);
	assert_eq!(run.status, "relay saved\nThe server must be restarted.\n");
}

#[test]
fn dry_run_prints_the_diff_and_writes_nothing() {
	let run = run(&["remove", "--dry-run"], "", true);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert!(
		run.out.contains("-host = 'smtp.example.net'"),
		"{}",
		run.out
	);
	assert_eq!(run.after, run.before, "dry-run must not write");
	assert!(run.status.is_empty(), "dry-run must not report a save");
}

#[test]
fn invalid_input_is_refused_and_leaves_the_file_untouched() {
	for (args, stdin, message) in [
		(
			vec!["add", "--host", "h.example.net", "--username", "u"],
			"p\n",
			"--username requires --starttls: credentials are never sent in plaintext",
		),
		(
			vec![
				"add",
				"--domain",
				"x.org",
				"--host",
				"h.example.net",
				"--starttls",
				"--username",
				"u",
			],
			"",
			"--username needs --password-stdin: pipe the password in as one line",
		),
		(
			vec!["add", "--host", "h.example.net", "--password-stdin"],
			"p\n",
			"--password-stdin needs --username",
		),
		(
			vec!["add", "--host", "bad host"],
			"",
			"--host \"bad host\" is not a host name or address (letters, digits, '-', '.', '_' and ':')",
		),
		(
			vec!["add", "--host", "h.example.net", "--socks-proxy", "proxy"],
			"",
			"--socks-proxy \"proxy\" must be HOST:PORT",
		),
		(
			vec!["add", "--host", "h.example.net", "--port", "0"],
			"",
			"--port must be between 1 and 65535",
		),
		(
			vec!["add", "--account", "a@b", "--host", "h.example.net"],
			"",
			"--account \"a@b\" is not a local account name",
		),
		(
			vec!["add", "--domain", "example.org", "--host", "h.example.net"],
			"",
			"Domain example.org already has a Fail transport rule; remove it from the configuration first",
		),
		(
			vec![
				"add",
				"--host",
				"h.example.net",
				"--starttls",
				"--username",
				"u",
				"--password-stdin",
			],
			"pa${HOME}ss\n",
			"the relay password contains \"${\", which the configuration loader would expand as an environment reference",
		),
		(
			vec![
				"add",
				"--host",
				"h.example.net",
				"--starttls",
				"--username",
				"u",
				"--password-stdin",
			],
			"",
			"no relay password on stdin: pipe it in as one line",
		),
		(
			vec!["remove", "--account", "alice"],
			"",
			"no relay is configured for account alice",
		),
		(
			vec!["remove", "--domain", "example.org"],
			"",
			"no relay is configured for domain example.org",
		),
	] {
		let run = run(&args, stdin, false);
		assert_eq!(run.result.unwrap_err(), message, "{args:?}");
		assert!(run.after == run.before, "{args:?} must not change the file");
	}
}

#[test]
fn remove_leaves_a_non_relay_rule_with_the_same_selector_alone() {
	let (_dir, file) = test_config(
		"\n[[transport]]\ndomain = 'example.net'\nkind = 'fail'\n\n[[transport]]\ndomain = 'example.net'\nkind = 'relay'\nhost = 'smtp.example.net'\nport = 25\n",
	);
	let before = std::fs::read_to_string(file.path()).unwrap();
	execute_with(
		file.path(),
		parse(&["remove", "--domain", "example.net"]),
		false,
		&mut std::io::BufReader::new(std::io::empty()),
		&mut Vec::new(),
		&mut Vec::new(),
		no_restart,
	)
	.unwrap();
	assert_eq!(
		std::fs::read_to_string(file.path()).unwrap(),
		before.replace(
			"\n[[transport]]\ndomain = 'example.net'\nkind = 'relay'\nhost = 'smtp.example.net'\nport = 25\n",
			""
		),
		"only the relay rule may be removed; the fail rule for the same domain stays"
	);
}
