//! `write_executable` while other threads fork: the stub must run at once.

use crate::test_executable::write_executable;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn a_stub_runs_right_after_it_is_written_while_other_threads_fork() {
	let stop = Arc::new(AtomicBool::new(false));
	let noise: Vec<_> = (0..8)
		.map(|_| {
			let stop = stop.clone();
			std::thread::spawn(move || {
				while !stop.load(Ordering::Relaxed) {
					let _ = Command::new("/bin/true").status();
				}
			})
		})
		.collect();
	let dir = tempfile::tempdir().unwrap();
	for round in 0..100 {
		let stub = dir.path().join(format!("stub{round}"));
		write_executable(&stub, format!("#!/bin/sh\nexit {}\n", round % 7));
		let status = Command::new(&stub).status().unwrap_or_else(|error| {
			panic!("round {round}: {error}");
		});
		assert_eq!(status.code(), Some(round % 7));
	}
	stop.store(true, Ordering::Relaxed);
	for thread in noise {
		thread.join().unwrap();
	}
}
