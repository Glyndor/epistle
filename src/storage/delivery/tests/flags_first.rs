//! A delivered message is never visible before its flags file: a reader
//! that lists `new/` and finds the `.eml` also finds the `.flags`.

use std::sync::Barrier;

use super::base::{directory, message};
use super::*;

/// How many deliveries are raced against a reader.
const ROUNDS: usize = 150;

#[test]
fn a_visible_message_already_has_its_flags_file() {
	for _ in 0..ROUNDS {
		let dir = tempfile::tempdir().expect("tempdir");
		let account = dir.path().join("accounts").join("alice");
		fs::create_dir_all(&account).expect("mkdir");
		fs::write(account.join("filter.sieve"), "addflag \"\\\\Seen\"; keep;").expect("filter");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		let new_dir = account.join("new");
		let start = Barrier::new(2);
		std::thread::scope(|scope| {
			let reader = scope.spawn(|| {
				start.wait();
				loop {
					let eml = fs::read_dir(&new_dir).ok().and_then(|entries| {
						entries
							.flatten()
							.map(|entry| entry.path())
							.find(|path| path.extension().is_some_and(|ext| ext == "eml"))
					});
					if let Some(eml) = eml {
						return fs::read_to_string(eml.with_extension("flags"));
					}
					std::thread::yield_now();
				}
			});
			start.wait();
			delivery
				.deliver(message(&["alice@example.org"]))
				.expect("deliver");
			let flags = reader.join().expect("reader");
			let flags = flags.expect("the flags file exists once the message is visible");
			assert!(flags.contains("seen"), "{flags}");
		});
	}
}
