//! Overlapping UPDATE states must remove and journal each UID only once.

use super::harness::*;

const MESSAGE: &[u8] = b"Subject: concurrent canary\r\n\r\nkeep me\r\n";

fn uid(n: u128) -> String {
	uuid::Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 + n).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_quits_journal_the_union_of_deletions_exactly_once() {
	let server = Harness::start(|s| s).await;
	let ids = [uid(1), uid(2), uid(3), uid(4)];
	let paths = ids.each_ref().map(|id| server.seed("tester", id, MESSAGE));
	let mut one = server.login("tester", 4).await;
	let mut two = server.login("tester", 4).await;
	// Both sessions delete UID 2; each also deletes a UID the other keeps.
	for (client, numbers) in [(&mut one, [1, 2]), (&mut two, [2, 3])] {
		for n in numbers {
			send(client, format!("DELE {n}\r\n").as_bytes()).await;
			expect(client, &format!("+OK message {n} deleted\r\n")).await;
		}
	}
	// Both deletion sets are established before either QUIT is sent.
	tokio::join!(quit(&mut one), quit(&mut two));
	for path in &paths[..3] {
		assert!(!path.exists(), "committed deletion survived: {path:?}");
	}
	assert_eq!(std::fs::read(&paths[3]).expect("survivor"), MESSAGE);
	let journal = std::fs::read_to_string(server.data.path().join("accounts/tester/.jmap_changes"))
		.expect("change journal");
	for (index, id) in ids.iter().enumerate() {
		let count = journal
			.lines()
			.filter(|line| line.ends_with(&format!(" E D {id}")))
			.count();
		assert_eq!(count, usize::from(index < 3), "destroyed events for {id}");
	}
	let mut fresh = server.login("tester", 1).await;
	send(&mut fresh, b"UIDL 1\r\n").await;
	expect(&mut fresh, &format!("+OK 1 {}\r\n", ids[3])).await;
	quit(&mut fresh).await;
	server.healthy().await;
}
