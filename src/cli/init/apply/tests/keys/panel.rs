//! The panel's secrets through the two entry points `init` uses: the plan the
//! operator reads and the apply phase that writes.

use std::fmt::Write as _;

use super::*;
use crate::cli::init::compose::panel_secrets::{
	admin_id_path, api_token_path, session_secret_path,
};

const IMAGE: &str = "ghcr.io/glyndor/epistle-panel:0.3.1";

struct Install {
	_dir: tempfile::TempDir,
	answers: Answers,
}

/// Answers for a fresh install under a tempdir, running the panel when
/// `panel` is set.
fn install(panel: bool) -> Install {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = super::reuse::answers_minimal();
	answers.data_dir = dir.path().join("data");
	answers.config_path = dir.path().join("mail.toml");
	answers.services.api = true;
	answers.services.panel_image = panel.then(|| IMAGE.to_string());
	Install { _dir: dir, answers }
}

fn panel_step(answers: &Answers) -> Option<String> {
	plan(answers)
		.expect("plan")
		.steps
		.iter()
		.find(|step| matches!(step, PlanStep::PanelSecrets { .. }))
		.map(|step| {
			let mut text = String::new();
			write!(&mut text, "{step}").expect("render");
			text
		})
}

fn secrets_of(answers: &Answers) -> Vec<String> {
	[
		api_token_path(&answers.data_dir),
		session_secret_path(&answers.data_dir),
		admin_id_path(&answers.data_dir),
	]
	.iter()
	.map(|path| std::fs::read_to_string(path).expect("secret"))
	.collect()
}

#[test]
fn the_plan_lists_the_panel_secrets_only_when_the_stack_runs_the_panel() {
	assert!(panel_step(&install(false).answers).is_none());
	let with = install(true);
	let line = panel_step(&with.answers).expect("the plan names the panel secrets");
	assert!(line.contains("create the key"), "{line}");
	assert!(line.contains("generate"), "{line}");
	assert!(
		line.contains(&api_token_path(&with.answers.data_dir).display().to_string()),
		"{line}"
	);
	assert!(
		line.contains(
			&session_secret_path(&with.answers.data_dir)
				.display()
				.to_string()
		),
		"{line}"
	);
}

#[test]
fn apply_writes_the_panel_secrets_and_the_key_when_the_stack_runs_the_panel() {
	let install = install(true);
	let outcome = apply(&install.answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	for path in [
		api_token_path(&install.answers.data_dir),
		session_secret_path(&install.answers.data_dir),
	] {
		assert!(
			outcome
				.report
				.steps
				.iter()
				.any(|step| matches!(step, ReportStep::Wrote(p) if p == &path)),
			"{path:?} not reported: {:?}",
			outcome.report.steps
		);
	}
	let keys = std::fs::read_to_string(install.answers.data_dir.join("api_keys.toml"))
		.expect("api_keys.toml");
	assert!(keys.contains("label = \"panel\""), "{keys}");
}

#[test]
fn apply_writes_nothing_of_the_panel_when_the_stack_does_not_run_it() {
	let install = install(false);
	let outcome = apply(&install.answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	assert!(!api_token_path(&install.answers.data_dir).exists());
	assert!(!session_secret_path(&install.answers.data_dir).exists());
	assert!(!install.answers.data_dir.join("api_keys.toml").exists());
}

#[test]
fn a_second_apply_reuses_them_and_the_plan_says_so_beforehand() {
	let install = install(true);
	assert!(apply(&install.answers).error.is_none());
	let before = secrets_of(&install.answers);
	let line = panel_step(&install.answers).expect("step");
	assert!(
		line.contains("reuse the key") && line.contains("reuse "),
		"{line}"
	);
	let outcome = apply(&install.answers);
	assert!(outcome.error.is_none());
	assert_eq!(secrets_of(&install.answers), before);
}

#[test]
fn nothing_the_operator_is_shown_carries_a_secret() {
	let install = install(true);
	let mut shown = String::new();
	plan(&install.answers)
		.expect("plan")
		.write_to(&mut shown)
		.expect("plan text");
	let outcome = apply(&install.answers);
	assert!(outcome.error.is_none());
	outcome
		.report
		.write_to(&mut ShownBuffer(&mut shown))
		.expect("report");
	write!(&mut shown, "{:?}", outcome.report).expect("debug");
	shown.push_str(&panel_step(&install.answers).expect("step"));
	for secret in secrets_of(&install.answers) {
		assert!(secret.len() >= 32);
		assert!(
			!shown.contains(secret.trim()),
			"a secret reached what the operator reads"
		);
	}
}

struct ShownBuffer<'a>(&'a mut String);

impl std::io::Write for ShownBuffer<'_> {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.push_str(&String::from_utf8_lossy(bytes));
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

#[test]
fn an_unusable_panel_secret_stops_the_plan_and_the_apply_before_the_config_is_written() {
	let install = install(true);
	std::fs::create_dir_all(api_token_path(&install.answers.data_dir)).expect("dir");
	let error = plan(&install.answers)
		.expect_err("planning refuses it too")
		.to_string();
	assert!(error.contains("path is not a regular file"), "{error}");
	let outcome = apply(&install.answers);
	let error = outcome.error.expect("apply refuses").to_string();
	assert!(error.contains("path is not a regular file"), "{error}");
	assert!(
		!install.answers.config_path.exists(),
		"the config is not written behind a refusal"
	);
}
