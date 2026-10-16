//! `epistle init --answers FILE --json`: the plan, and what was written,
//! as one object.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

/// Answers for a manual setup under the environment's temporary directory.
fn answers(env: &Env) -> String {
	let root = env.dir.path();
	let path = root.join("answers.toml");
	std::fs::write(
		&path,
		format!(
			"mode = \"manual\"\nhostname = \"mail.example.org\"\ndomains = [\"example.org\"]\n\
			 data_dir = \"{data}\"\nconfig_path = \"{config}\"\nimage = \"localhost/epistle:dev\"\n\n\
			 [services]\nimap = true\nsubmission = true\ndatabase = false\n",
			data = root.join("init-data").display(),
			config = root.join("init-etc/mail.toml").display(),
		),
	)
	.expect("write answers");
	path.to_string_lossy().into_owned()
}

fn init(env: &Env, extra: &[&str]) -> (i32, Value) {
	let answers = answers(env);
	let mut args = vec!["init", "--answers", &answers, "--json"];
	args.extend_from_slice(extra);
	json(&epistle(&args, b""))
}

#[test]
fn a_dry_run_prints_the_plan_and_writes_nothing() {
	let env = env("");
	let (code, plan) = init(&env, &["--dry-run"]);
	assert_eq!(code, 0);
	assert_eq!(plan["result"], "dry-run");
	assert_eq!(plan["action"], "init");
	assert_eq!(
		plan["config"],
		env.dir
			.path()
			.join("init-etc/mail.toml")
			.display()
			.to_string()
	);
	assert_eq!(plan["report"], json!([]));
	let lines = plan["plan"].as_array().expect("plan is a list");
	assert!(
		lines
			.iter()
			.any(|line| line.as_str().is_some_and(|line| line.contains("mail.toml"))),
		"the plan should name the configuration it would write: {lines:?}"
	);
	assert!(
		!env.dir.path().join("init-etc").exists() && !env.dir.path().join("init-data").exists(),
		"a dry run wrote something"
	);
}

#[test]
fn a_real_run_reports_what_it_wrote() {
	let env = env("");
	let (code, done) = init(&env, &[]);
	assert_eq!(code, 0, "{done}");
	assert_eq!(done["result"], "saved");
	assert!(
		done["report"]
			.as_array()
			.is_some_and(|report| !report.is_empty()),
		"the report of a real run is empty: {done}"
	);
	assert!(env.dir.path().join("init-etc/mail.toml").is_file());
}
