use super::*;

/// A claim takes its own account's lock and no other: with every other
/// lock held, it still goes through.
#[test]
fn a_claim_waits_only_on_its_own_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = (0..1000)
		.map(|n| format!("user{n}"))
		.find(|name| !std::ptr::eq(stripe(name), &CLAIM[0]))
		.expect("a name off the first stripe");
	let own = stripe(&account);
	let _others: Vec<_> = CLAIM
		.iter()
		.filter(|lock| !std::ptr::eq(*lock, own))
		.map(|lock| lock.lock().unwrap_or_else(PoisonError::into_inner))
		.collect();
	let (done, finished) = std::sync::mpsc::channel();
	let data = dir.path().to_path_buf();
	std::thread::spawn(move || {
		let _ = done.send(claim(&data, &account, "carol@example.net", 7));
	});
	let claimed = finished
		.recv_timeout(Duration::from_secs(10))
		.expect("other accounts' locks do not hold this claim up");
	assert!(claimed, "first reply to carol is due");
}
