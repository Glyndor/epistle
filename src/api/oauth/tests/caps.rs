//! The cap on sessions (refresh families) per account: ending the oldest or
//! refusing the new one, and grants racing for the last place.

use std::sync::{Arc, Barrier};

use super::super::refresh::{FirstToken, SessionCap, Started, live_records, start_family};
use crate::limits::Cap;

fn cap(value: u64, refuse: bool) -> SessionCap {
	SessionCap {
		cap: Some(Cap {
			value,
			set_by: "the server".into(),
		}),
		refuse,
	}
}

fn start(dir: &std::path::Path, n: u64, session: &SessionCap) -> Started {
	let (token, family) = (format!("token-{n}"), format!("family-{n}"));
	let first = FirstToken {
		token: &token,
		family: &family,
		account: "alice",
		scope: "read",
		credential: "",
	};
	start_family(dir, &first, 10_000 + n, 1, session).expect("start")
}

#[test]
fn the_oldest_session_ends_when_the_account_is_full() {
	let dir = tempfile::tempdir().unwrap();
	let session = cap(3, false);
	for n in 0..5 {
		assert!(matches!(start(dir.path(), n, &session), Started::Opened));
	}
	assert_eq!(live_records(dir.path()), 3);
}

#[test]
fn a_new_session_is_refused_when_the_policy_says_so() {
	let dir = tempfile::tempdir().unwrap();
	let session = cap(2, true);
	assert!(matches!(start(dir.path(), 0, &session), Started::Opened));
	assert!(matches!(start(dir.path(), 1, &session), Started::Opened));
	match start(dir.path(), 2, &session) {
		Started::Full { held, cap } => assert_eq!((held, cap.value), (2, 2)),
		Started::Opened => panic!("the third must be refused"),
	}
	assert_eq!(
		live_records(dir.path()),
		2,
		"nothing was written for the refused one"
	);
}

#[test]
fn a_cap_of_zero_refuses_whatever_the_policy() {
	let dir = tempfile::tempdir().unwrap();
	assert!(matches!(
		start(dir.path(), 0, &cap(0, false)),
		Started::Full { .. }
	));
}

#[test]
fn no_cap_means_no_session_is_ended() {
	let dir = tempfile::tempdir().unwrap();
	let none = SessionCap {
		cap: None,
		refuse: false,
	};
	for n in 0..60 {
		start(dir.path(), n, &none);
	}
	assert_eq!(live_records(dir.path()), 60);
}

#[test]
fn racing_grants_admit_exactly_the_cap_when_refusing_and_never_pass_it_when_ending() {
	const WRITERS: u64 = 8;
	const CAP: u64 = 3;
	for refuse in [true, false] {
		let dir = tempfile::tempdir().unwrap();
		let barrier = Arc::new(Barrier::new(WRITERS as usize));
		let handles: Vec<_> = (0..WRITERS)
			.map(|n| {
				let (barrier, path) = (Arc::clone(&barrier), dir.path().to_path_buf());
				std::thread::spawn(move || {
					barrier.wait();
					start(&path, n, &cap(CAP, refuse))
				})
			})
			.collect();
		let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
		let opened = results
			.iter()
			.filter(|r| matches!(r, Started::Opened))
			.count() as u64;
		if refuse {
			assert_eq!(opened, CAP);
		} else {
			assert_eq!(opened, WRITERS);
		}
		assert_eq!(live_records(dir.path()) as u64, CAP, "refuse = {refuse}");
	}
}
