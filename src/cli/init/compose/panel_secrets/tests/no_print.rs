//! No secret reaches the report, the plan or an error.

use super::*;
use crate::cli::init::plan::PlanStep;

/// Everything a run can show an operator, as one string.
fn shown(report: &Report) -> String {
	let mut text = format!("{report:?}\n");
	report.write_to(&mut text_writer(&mut text)).expect("write");
	text
}

fn text_writer(buffer: &mut String) -> impl std::io::Write + '_ {
	struct Sink<'a>(&'a mut String);
	impl std::io::Write for Sink<'_> {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			self.0.push_str(&String::from_utf8_lossy(bytes));
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}
	Sink(buffer)
}

fn assert_hidden(layout: &Layout, shown: &str, what: &str) {
	for path in paths(&layout.data) {
		let secret = text(&path);
		assert!(secret.len() >= 32, "{path:?} holds a secret to look for");
		assert!(
			!shown.contains(secret.trim()),
			"{what} shows the secret in {path:?}: {shown}"
		);
	}
}

#[test]
fn the_report_of_a_first_run_names_paths_and_never_a_secret() {
	let layout = layout();
	let report = run(&layout, NOW);
	assert_hidden(&layout, &shown(&report), "the first report");
}

#[test]
fn the_reports_of_a_reuse_a_rotation_and_a_renewal_never_show_a_secret() {
	let layout = layout();
	run(&layout, NOW);
	let reuse = run(&layout, NOW + DAY);
	assert_hidden(&layout, &shown(&reuse), "the reuse report");
	std::fs::remove_file(api_token_path(&layout.data)).expect("remove");
	let rotate = run(&layout, NOW + 2 * DAY);
	assert_hidden(&layout, &shown(&rotate), "the rotation report");
	let renew = run(&layout, NOW + 340 * DAY);
	assert_hidden(&layout, &shown(&renew), "the renewal report");
}

#[test]
fn the_plan_step_names_paths_and_verbs_and_never_a_secret() {
	let layout = layout();
	run(&layout, NOW);
	let decision = decide(&layout.data, NOW + 340 * DAY).expect("decide");
	let step = PlanStep::PanelSecrets {
		api_token: api_token_path(&layout.data),
		key: decision.key.to_string(),
		session_secret: session_secret_path(&layout.data),
		session: decision.session.to_string(),
	};
	let line = step.to_string();
	assert!(line.contains("renew the key"), "{line}");
	assert!(
		line.contains(&api_token_path(&layout.data).display().to_string()),
		"{line}"
	);
	assert_hidden(&layout, &line, "the plan step");
}

#[test]
fn an_error_names_the_path_and_not_the_secret() {
	let layout = layout();
	run(&layout, NOW);
	std::fs::write(session_secret_path(&layout.data), "short").expect("write");
	let secret = text(&api_token_path(&layout.data));
	let message = refusal(&layout, NOW + DAY);
	assert!(!message.contains(secret.trim()), "{message}");
	assert!(!message.contains("short\n"), "{message}");
}
