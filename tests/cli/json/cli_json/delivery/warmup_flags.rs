//! What `--all`, `--force` and `--yes` do on `warmup plan` and `warmup start`,
//! read from the real binary: the plan it prints, the exit code, and what
//! reaches `warmup.json`.

use serde_json::Value;

use crate::harness::{Env, env, epistle, json};

fn fresh() -> Env {
	env("[storage]\ndelivery_log_days = 30\n")
}

fn warmup(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = vec!["warmup", "--config", env.config.as_str()];
	full.extend_from_slice(args);
	epistle(&full, b"")
}

/// The JSON object of `warmup <args> --json`, with the two values that
/// depend on the day the test runs on taken out.
fn plan(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = args.to_vec();
	full.push("--json");
	let (code, mut value) = json(&warmup(env, &full));
	if let Some(object) = value.as_object_mut() {
		object.remove("day");
	}
	if let Some(groups) = value["groups"].as_array_mut() {
		for group in groups {
			if let Some(row) = group.as_object_mut() {
				row.remove("reach");
			}
		}
	}
	(code, value)
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The orders and the switch in `warmup.json`, as the server will read them.
fn settings(env: &Env) -> Value {
	let text = std::fs::read_to_string(env.data_dir().join("warmup.json")).expect("warmup.json");
	serde_json::from_str(&text).expect("warmup.json is JSON")
}

/// Put gmail's cap at 5000 so a plan that starts it at 50 would lower it.
fn gmail_at_5000(env: &Env) {
	let output = warmup(env, &["set", "gmail", "--cap", "5000", "--yes"]);
	assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn all_is_the_default_and_cannot_be_mixed_with_a_group() {
	let env = fresh();
	let base = ["plan", "--ip-age", "0d", "--daily-volume", "1000"];
	let (code, without) = plan(&env, &base);
	assert_eq!(code, 0);
	assert_eq!(without["groups"].as_array().expect("groups").len(), 7);
	let mut with = base.to_vec();
	with.push("--all");
	assert_eq!(plan(&env, &with), (0, without));

	let mut both = base.to_vec();
	both.extend(["--all", "--group", "gmail"]);
	let output = warmup(&env, &both);
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert!(
		stderr(&output).contains("cannot be used with"),
		"{}",
		stderr(&output)
	);
}

#[test]
fn start_with_all_writes_what_start_without_it_writes() {
	let (with, without) = (fresh(), fresh());
	for (env, extra) in [(&with, &["--all"][..]), (&without, &[][..])] {
		let mut args = vec!["start", "--ip-age", "0d", "--daily-volume", "1000", "--yes"];
		args.extend_from_slice(extra);
		let (code, value) = plan(env, &args);
		assert_eq!(code, 0, "{value}");
		assert_eq!(value["groups"].as_array().expect("groups").len(), 7);
	}
	let written = settings(&with);
	assert_eq!(written["enabled"], Value::Bool(true));
	assert_eq!(written["orders"].as_array().expect("orders").len(), 7);
	assert_eq!(written, settings(&without));
}

#[test]
fn force_changes_the_plan_and_yes_does_not() {
	let env = fresh();
	gmail_at_5000(&env);
	let file = env.data_dir().join("warmup.json");
	let before = std::fs::read(&file).expect("warmup.json");
	let base = [
		"plan",
		"--ip-age",
		"0d",
		"--daily-volume",
		"1000",
		"--group",
		"gmail",
	];

	let (code, kept) = plan(&env, &base);
	assert_eq!(code, 0);
	let row = &kept["groups"][0];
	assert_eq!(
		(row["cap"].as_u64(), row["current"].as_u64()),
		(Some(50), Some(5000))
	);
	assert_eq!(row["applies"], Value::Bool(false), "a lower cap is kept");

	let mut forced = base.to_vec();
	forced.push("--force");
	let (_, lowered) = plan(&env, &forced);
	assert_eq!(
		lowered["groups"][0]["applies"],
		Value::Bool(true),
		"--force lowers it"
	);

	// The confirmation belongs to `start`: `plan --yes` is the same plan.
	let mut confirmed = base.to_vec();
	confirmed.push("--yes");
	assert_eq!(plan(&env, &confirmed), (0, kept));

	assert_eq!(
		std::fs::read(&file).expect("warmup.json"),
		before,
		"a plan writes nothing"
	);
}

#[test]
fn start_keeps_a_higher_cap_unless_forced() {
	let env = fresh();
	gmail_at_5000(&env);
	let base = [
		"start",
		"--ip-age",
		"0d",
		"--daily-volume",
		"1000",
		"--group",
		"gmail",
		"--yes",
	];
	let (code, kept) = plan(&env, &base);
	assert_eq!(code, 0);
	assert_eq!(kept["groups"][0]["applies"], Value::Bool(false));
	let order = |env: &Env| settings(env)["orders"][0]["action"].clone();
	assert_eq!(order(&env), serde_json::json!({"set": {"cap": 5000}}));

	let mut forced = base.to_vec();
	forced.push("--force");
	let (code, lowered) = plan(&env, &forced);
	assert_eq!(code, 0);
	assert_eq!(lowered["groups"][0]["applies"], Value::Bool(true));
	assert_eq!(order(&env), serde_json::json!({"force": {"cap": 50}}));
}

#[test]
fn start_without_yes_off_a_terminal_is_refused_and_writes_nothing() {
	let env = fresh();
	let output = warmup(&env, &["start", "--ip-age", "0d", "--all"]);
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert!(!env.data_dir().join("warmup.json").exists());
}
