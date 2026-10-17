//! Several changes as one step, under the state the caller expects.

use super::*;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

#[test]
fn a_caller_that_expects_an_old_state_changes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let before = s.state().expect("state");
	s.create("a", "keep;\r\n").expect("a");
	let outcome = s.transact(Some(before), |tx| tx.create("b", "keep;\r\n"));
	assert_eq!(outcome.map(|_| ()), Err(StoreError::StateMismatch));
	assert!(s.get("b").is_err());
	let now = s.state().expect("state");
	assert_eq!(
		s.transact(Some(now), |tx| tx.create("b", "keep;\r\n"))
			.map(|r| r.map(|_| ())),
		Ok(Ok(()))
	);
}

#[test]
fn many_changes_in_one_step_move_the_state_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let before = s.state().expect("state");
	let (inside, ids) = s
		.transact(None, |tx| {
			let a = tx.create("a", "keep;\r\n").expect("a");
			let b = tx.create("b", "discard;\r\n").expect("b");
			tx.set_active(Some(&a.id)).expect("activate");
			tx.update(&b.id, Some("c"), None).expect("rename");
			(tx.state(), (a.id, b.id))
		})
		.expect("transact");
	assert_eq!(inside, before + 1);
	assert_eq!(s.state().expect("state"), before + 1);
	assert_eq!(s.active_name().as_deref(), Some("a"));
	assert_eq!(s.get("c").expect("c"), "discard;\r\n");
	assert_eq!(s.list().expect("list").len(), 2);
	// What the step handed out is what the store keeps.
	let listed: Vec<String> = s.list().expect("list").into_iter().map(|i| i.id).collect();
	assert!(
		listed.contains(&ids.0) && listed.contains(&ids.1),
		"{listed:?} vs {ids:?}"
	);
}

#[test]
fn the_lock_is_held_across_the_whole_step() {
	// Another store on the same account has to wait: it never sees the step
	// half done.
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let s = store(dir.path());
	let seen = s
		.transact(None, |tx| {
			tx.create("a", "keep;\r\n").expect("a");
			let (sender, receiver) = std::sync::mpsc::channel();
			let other = {
				let root = root.clone();
				std::thread::spawn(move || {
					let names: Vec<String> = ScriptStore::new(&root, "alice")
						.list()
						.expect("list")
						.into_iter()
						.map(|s| s.name)
						.collect();
					let _ = sender.send(names);
				})
			};
			// While the step is open the other store has not answered.
			let early = receiver
				.recv_timeout(std::time::Duration::from_millis(300))
				.is_ok();
			tx.create("b", "keep;\r\n").expect("b");
			(early, other, receiver)
		})
		.expect("transact");
	let (early, other, receiver) = seen;
	assert!(!early, "the other store listed in the middle of the step");
	assert_eq!(
		receiver.recv().expect("answer"),
		vec!["a".to_string(), "b".to_string()]
	);
	other.join().expect("join");
}

#[test]
fn of_several_callers_expecting_one_state_one_wins() {
	for _ in 0..10 {
		let dir = tempfile::tempdir().expect("tempdir");
		let root = dir.path().to_path_buf();
		let state = store(dir.path()).state().expect("state");
		let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
		let handles: Vec<_> = (0..6)
			.map(|n| {
				let (root, barrier) = (root.clone(), barrier.clone());
				std::thread::spawn(move || {
					barrier.wait();
					ScriptStore::new(&root, "alice")
						.transact(Some(state), |tx| {
							tx.create(&format!("s{n}"), "keep;\r\n").map(|_| ())
						})
						.is_ok()
				})
			})
			.collect();
		let wins = handles
			.into_iter()
			.filter_map(|h| h.join().ok())
			.filter(|ok| *ok)
			.count();
		assert_eq!(wins, 1);
		assert_eq!(store(dir.path()).list().expect("list").len(), 1);
	}
}
