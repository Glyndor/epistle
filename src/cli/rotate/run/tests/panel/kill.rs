//! The run killed between any two of its writes: at every one of those
//! points the key file holds the secret of the stored key, and the next run
//! finishes without rotating the key twice or leaving the old container.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use super::super::abort::ABORT_AT;
use super::*;

/// The configuration the child rotates.
const CONFIG: &str = "EPISTLE_TEST_ROTATE_PANEL_CONFIG";

/// The child: rotate the configuration the parent names, then stop. Without
/// the variable it is an ordinary test that does nothing.
#[test]
fn child_rotates_the_panels_key_until_the_switch() {
	let Some(config) = std::env::var_os(CONFIG) else {
		return;
	};
	let ran = run(Path::new(&config), NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
}

/// The state of the container's step in the journal of a run cut short.
fn container_step(install: &Install) -> String {
	let text = std::fs::read_to_string(install.data.join("rotate/journal.json")).unwrap();
	let journal: serde_json::Value = serde_json::from_str(&text).unwrap();
	journal["steps"]
		.as_array()
		.unwrap()
		.iter()
		.find(|step| step["kind"] == "panel-recreate")
		.and_then(|step| step["state"].as_str())
		.expect("the journal has the container's step")
		.to_string()
}

#[test]
fn a_run_killed_at_any_checkpoint_leaves_the_file_and_the_key_agreeing() {
	let mut killed = 0;
	for at in 1.. {
		let install = install_with_panel();
		compose(&install, &["mail", "panel"]);
		let before = stored(&install, "panel");
		let status = Command::new(std::env::current_exe().expect("test binary"))
			.args([
				"--exact",
				"cli::rotate::run::tests::panel::kill::child_rotates_the_panels_key_until_the_switch",
				"--test-threads=1",
			])
			.env(CONFIG, &install.config)
			.env(ABORT_AT, at.to_string())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.expect("run the child");
		if status.success() {
			assert!(file_is_the_stored_key(&install));
			break;
		}
		assert_eq!(
			status.signal(),
			Some(libc::SIGABRT),
			"the child stopped at checkpoint {at} for another reason"
		);
		killed += 1;
		assert!(
			file_is_the_stored_key(&install),
			"after a kill at checkpoint {at} the file is not the stored key's"
		);
		let container_left = container_step(&install) != "done";
		let ran = run(&install.config, NOW + 60, true, ExitCode::SUCCESS);
		assert_eq!(
			ran.code,
			ExitCode::SUCCESS,
			"after a kill at checkpoint {at}: {}",
			ran.status
		);
		assert!(file_is_the_stored_key(&install), "checkpoint {at}");
		assert!(stored(&install, "panel") != before, "checkpoint {at}");
		// Rotated once: the stored hash is the one the first run decided.
		let last = std::fs::read_to_string(install.data.join("rotate/last-run.json")).unwrap();
		assert!(last.contains(&stored(&install, "panel")), "checkpoint {at}");
		// The container is made again by the run that finds its step open,
		// and by no other.
		assert_eq!(
			ran.actions.len(),
			usize::from(container_left),
			"checkpoint {at}: {:?}",
			ran.actions
		);
	}
	// Three steps, three checkpoints each.
	assert_eq!(killed, 9, "the run did not stop where it should have");
}
