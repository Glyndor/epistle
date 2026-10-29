use super::base::{ALERTS, run};
use super::*;

const ADD: [&str; 12] = [
	"add",
	"disk-full",
	"--metric",
	"deferred",
	"--op",
	">",
	"--threshold",
	"10",
	"--window",
	"5m",
	"--email",
	"ops@example.org",
];

#[test]
fn add_appends_a_rule_with_seconds_and_a_default_cooldown() {
	let mut args = ADD.to_vec();
	args.extend(["--email", "oncall@example.org", "--webhook"]);
	let run = run(ALERTS, &args);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		format!(
			"{}\n[[alerts]]\nname = \"disk-full\"\nmetric = \"deferred\"\nop = \">\"\nthreshold = 10\nwindow_secs = 300\nwebhook = true\nemail = [\"ops@example.org\", \"oncall@example.org\"]\ncooldown_secs = 3600\n",
			run.before
		)
	);
	assert_eq!(run.status, "alert saved\nThe server must be restarted.\n");
}

#[test]
fn add_without_a_webhook_section_works_for_email_only_rules() {
	let run = run("", &ADD);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert!(
		run.after.contains("email = [\"ops@example.org\"]"),
		"{}",
		run.after
	);
	assert!(!run.after.contains("webhook"), "{}", run.after);
}

#[test]
fn add_dry_run_prints_the_diff_and_writes_nothing() {
	let run = super::base::run_with(ALERTS, &ADD, true);
	assert!(run.out.contains("+name = \"disk-full\""), "{}", run.out);
	assert_eq!(run.after, run.before);
}

/// `ADD` with one argument replaced by another.
fn with(args: &[&'static str], from: &str, to: &'static str) -> Vec<&'static str> {
	args.iter()
		.map(|arg| if *arg == from { to } else { arg })
		.collect()
}

#[test]
fn invalid_requests_are_refused_and_leave_the_file_untouched() {
	let metrics = crate::metrics::metric_names().join(", ");
	let webhook_only: Vec<&str> = ADD[..10].to_vec();
	for (args, message) in [
		(
			with(&ADD, "deferred", "not_a_counter"),
			format!("--metric \"not_a_counter\" is not a known counter; valid names: {metrics}"),
		),
		(
			webhook_only,
			"the rule needs somewhere to go: pass --webhook, --email, or both".to_string(),
		),
		(
			with(&ADD, "5m", "5x"),
			"--window \"5x\" must be a duration such as 90s, 5m, 1h or 2d (at most one year)".to_string(),
		),
		(with(&ADD, "5m", "0s"), "--window must be greater than zero".to_string()),
		(
			with(&ADD, "5m", "400d"),
			"--window \"400d\" must be a duration such as 90s, 5m, 1h or 2d (at most one year)".to_string(),
		),
		(
			[&ADD[..], &["--cooldown", "0"]].concat(),
			"--cooldown must be greater than zero".to_string(),
		),
		(
			with(&ADD, "disk-full", "bounce-storm"),
			"alert \"bounce-storm\" already exists; remove it first to change it".to_string(),
		),
		(
			with(&ADD, "disk-full", " "),
			"the rule name must be 1 to 128 characters without control characters".to_string(),
		),
		(
			with(&ADD, "ops@example.org", "no-at-sign"),
			"invalid configuration: [[alerts]] \"disk-full\" email \"no-at-sign\" is not a syntactically valid address".to_string(),
		),
	] {
		let run = run(ALERTS, &args);
		assert_eq!(run.result.unwrap_err(), message, "{args:?}");
		assert!(run.after == run.before, "{args:?} must not change the file");
	}
	let mut webhook = ADD[..10].to_vec();
	webhook.push("--webhook");
	let run = run("", &webhook);
	assert_eq!(
		run.result.unwrap_err(),
		"--webhook needs a webhook endpoint: run `epistle webhook set` first"
	);
	assert!(run.after == run.before);
}
