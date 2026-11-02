//! Cases a third review found in the split: a dry run that created the lock
//! file, a restart that failed with the code the restart returned instead of
//! the documented 4, and a data directory that changed while a run waited for
//! the lock.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use super::finish::services;
use super::harness::{Install, Zone, run, run_failing_restart, with_stack, without_stack};
use crate::cli::dkim::split::Options;
use crate::dkim::split_state;

const SPLIT: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};
const DRY: Options = Options {
	dry_run: true,
	..SPLIT
};
const DRY_FINISH: Options = Options {
	dry_run: true,
	finish: true,
	..SPLIT
};

/// Every path under `dir` with its size, to compare before and after.
fn tree(dir: &Path) -> Vec<(PathBuf, u64)> {
	let mut found = Vec::new();
	let mut pending = vec![dir.to_path_buf()];
	while let Some(next) = pending.pop() {
		for entry in std::fs::read_dir(&next).expect("dir").flatten() {
			let meta = entry.metadata().expect("meta");
			if meta.is_dir() {
				pending.push(entry.path());
			}
			found.push((entry.path(), meta.len()));
		}
	}
	found.sort();
	found
}

// ---- a dry run writes nothing

#[test]
fn a_dry_run_leaves_the_data_directory_exactly_as_it_found_it() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let before = tree(&install.data());
	let zone = Zone::default();
	for options in [&DRY, &DRY_FINISH] {
		let (provider, resolver) = services(&zone);
		let (code, out, err, _) = run(&install, options, Some(provider), &resolver);
		assert_eq!(code, ExitCode::SUCCESS, "{out}{err}");
	}
	assert_eq!(tree(&install.data()), before, "no key, state or lock file");
	assert!(!install.data().join("dkim-split.lock").exists());
}

#[test]
fn a_dry_run_after_a_real_run_still_waits_for_the_lock() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	run(&install, &SPLIT, Some(provider), &resolver);
	assert!(install.data().join("dkim-split.lock").exists());
	let _first = split_state::lock(&install.data(), Duration::from_millis(100)).unwrap();
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &DRY, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("another dkim split is running"), "{err}");
}

// ---- a restart that fails is pending, and exits 4

#[test]
fn a_restart_that_fails_leaves_the_split_pending_and_exits_4() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, _, restarts) =
		run_failing_restart(&install, &SPLIT, Some(provider), &resolver, (false, 1));
	assert_eq!(restarts, 1, "the restart was attempted");
	assert_eq!(code, ExitCode::from(4), "{out}");
	assert!(out.contains("NOT confirmed to run the moved keys"), "{out}");
	assert_eq!(
		split_state::pending(&install.data(), |_| true).unwrap(),
		["b.example.org"]
	);
}

#[test]
fn the_json_of_a_restart_that_failed_says_so() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) =
		run_failing_restart(&install, &SPLIT, Some(provider), &resolver, (true, 2));
	assert_eq!(code, ExitCode::from(4), "{out}");
	let json: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
	assert_eq!(json["result"], "restart-pending");
	assert_eq!(json["reload"], "restart-failed");
}

#[test]
fn repeating_a_pending_restart_that_fails_again_exits_4() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	run(&install, &SPLIT, Some(provider), &resolver);
	with_stack(&install);
	let (provider, resolver) = services(&zone);
	let (code, out, _, restarts) =
		run_failing_restart(&install, &SPLIT, Some(provider), &resolver, (false, 1));
	assert_eq!(restarts, 1);
	assert_eq!(code, ExitCode::from(4), "{out}");
	assert!(out.contains("NOT confirmed to run the moved keys"), "{out}");
	assert_eq!(
		split_state::pending(&install.data(), |_| true).unwrap(),
		["b.example.org"],
		"still pending"
	);
}

// ---- the lock follows the data directory

/// The text of `install`'s configuration with its data directory moved.
fn move_data_dir(install: &Install, to: &Path) {
	let text = install.text().replace(
		&format!("data_dir = {:?}", install.data()),
		&format!("data_dir = {to:?}"),
	);
	assert!(text.contains(&format!("{to:?}")), "the data_dir line moved");
	std::fs::write(&install.config, text).expect("config");
}

#[test]
fn a_data_dir_that_changes_while_waiting_is_locked_where_the_run_acts() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let moved = install.dir.path().canonicalize().unwrap().join("moved");
	std::fs::create_dir_all(&moved).unwrap();
	let compose = crate::cli::init::compose_file_path(&moved);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(compose, "services: {}\n").unwrap();
	let zone = Zone::default();
	let held_old = split_state::lock(&install.data(), Duration::from_millis(100)).unwrap();
	let held_new = split_state::lock(&moved, Duration::from_millis(100)).unwrap();
	let (code, out) = std::thread::scope(|scope| {
		let waiting = scope.spawn(|| {
			let (provider, resolver) = services(&zone);
			let (code, out, err, _) = run(&install, &SPLIT, Some(provider), &resolver);
			(code, format!("{out}{err}"))
		});
		std::thread::sleep(Duration::from_millis(300));
		move_data_dir(&install, &moved);
		drop(held_old);
		std::thread::sleep(Duration::from_millis(700));
		assert!(
			!waiting.is_finished(),
			"the run acted while another one held the lock of the directory it acts on"
		);
		drop(held_new);
		waiting.join().unwrap()
	});
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	let state = split_state::read(&moved).unwrap();
	assert!(state["b.example.org"].restarted.is_some());
	assert!(
		!install.data().join("dkim-split.json").exists(),
		"nothing was recorded under the old directory"
	);
}
