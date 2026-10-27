//! Sanity check that the legacy tests file does not pin helpers
//! removed by the host-binary switch. The test bodies are kept
//! thin because the operator-facing logic moved to
//! `mod_tests_steps.rs`; a future drive-by edit cannot resurrect
//! `rewrite_default_image` without the regression suite
//! noticing. The string match looks for a `pub`-tagged function
//! declaration so the doc-comment that names the helper for
//! context does not trip the guard.

#[test]
fn stack_update_module_does_not_expose_a_rewrite_default_image_helper() {
	let module = include_str!("mod.rs");
	for line in module.lines() {
		assert!(
			!line.contains("fn rewrite_default_image"),
			"rewrite_default_image was the old behaviour for refreshing a CLI-tagged image; \
			 the host-binary default has no such image and the helper must not be reintroduced"
		);
	}
}

/// Both reads of the generated file happen with the common lock in hand, so a
/// fifo at that path would hold the lock until somebody opened the other end.
/// They have to name the file instead, inside a few seconds, and the database
/// check has to answer without waiting.
#[cfg(unix)]
#[test]
fn a_fifo_at_the_generated_compose_path_is_refused_instead_of_waited_on() {
	use super::{plan_has_database, plan_update};
	use crate::cli::init::compose_read::fifo_at;
	use std::sync::mpsc;
	use std::time::Duration;
	for linked in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let fifo = dir.path().join("compose.fifo");
		fifo_at(&fifo);
		let compose = dir.path().join("compose.yaml");
		if linked {
			std::os::unix::fs::symlink(&fifo, &compose).unwrap();
		} else {
			std::fs::rename(&fifo, &compose).unwrap();
		}
		let label = format!("a {} fifo", if linked { "linked" } else { "direct" });
		let reading = compose.clone();
		let (sender, receiver) = mpsc::channel();
		let planning = std::thread::spawn(move || {
			let data_dir = reading.parent().unwrap().to_path_buf();
			sender
				.send(plan_update(&reading, &data_dir, &[]).map(|_| ()))
				.ok();
		});
		let value = receiver.recv_timeout(Duration::from_secs(5));
		if value.is_err() {
			drop(std::fs::OpenOptions::new().write(true).open(&fifo));
		}
		let error = value
			.unwrap_or_else(|_| panic!("{label}: the update waited for a fifo writer"))
			.expect_err(&label);
		planning.join().expect("the planning thread panicked");
		assert!(error.contains("must be a regular file"), "{label}: {error}");
		assert!(
			error.contains(&compose.display().to_string()),
			"{label}: {error}"
		);
		assert!(
			!plan_has_database(&compose),
			"{label}: the database check must answer without waiting"
		);
	}
}
