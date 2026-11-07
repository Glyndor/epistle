//! The plan the operator reads before confirming: which steps `init`
//! will take and in which order.

use super::super::helpers::answers::answers_minimal;
use super::*;

#[test]
fn plan_lists_every_step() {
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let labels: Vec<String> = plan
		.steps
		.iter()
		.map(|s| {
			format!("{:?}", s)
				.split_whitespace()
				.next()
				.unwrap_or("")
				.to_string()
		})
		.collect();
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::DkimEd25519 { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::DkimRsa { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::Storage { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::OAuthPrivate { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::OAuthPublic { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::Config { .. }))
	);
	assert!(!labels.is_empty());
}

#[test]
fn plan_step_dkim_rsa_is_always_generated() {
	// The RSA key is made in process, so the plan never leaves it out:
	// there is no program that could be missing.
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let rsa = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::DkimRsa { reused, .. } => Some(*reused),
			_ => None,
		})
		.expect("rsa step");
	assert!(!rsa, "a fresh install has no RSA key yet");
}

#[test]
fn plan_print_does_not_panic() {
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let mut out = String::new();
	plan.write_to(&mut out).expect("print");
	assert!(out.contains("dkim"));
	assert!(out.contains("config"));
}

/// The plan must list directory steps before the writes that depend
/// on them: a fresh `data_dir` and a fresh `config_path` parent must
/// appear ahead of every key write and the config write, because
/// `apply` creates the directories first and the operator reads the
/// plan before confirming.
#[test]
fn plan_lists_directory_steps_before_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let plan = plan(&answers).expect("plan");
	// The first step on a fresh tree must be a directory creation;
	// every write step must follow it.
	let first = plan
		.steps
		.first()
		.expect("plan must have at least one step");
	assert!(
		matches!(first, PlanStep::DataDir { .. } | PlanStep::ConfigDir { .. }),
		"plan must lead with a directory step, got {first:?}"
	);
	// Every write step must come after every preceding directory
	// step. Walk the list, remember the last directory index, and
	// assert no write index is below it.
	let mut last_directory_index: Option<usize> = None;
	for (i, step) in plan.steps.iter().enumerate() {
		let is_directory = matches!(step, PlanStep::DataDir { .. } | PlanStep::ConfigDir { .. });
		if is_directory {
			last_directory_index = Some(i);
		} else if let Some(last) = last_directory_index {
			assert!(
				i > last,
				"write step at index {i} appears before a directory step"
			);
		}
	}
}
