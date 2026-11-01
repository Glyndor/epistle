//! Two sessions on one maildrop, and another protocol working on it, while a
//! POP3 session holds deletions it has not committed yet.

use super::harness::*;

const MESSAGE: &[u8] = b"Subject: canary\r\n\r\nbody\r\n";

/// A unique id that sorts after every smaller `n`, as arrival order does.
fn uid(n: u128) -> String {
	uuid::Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 + n).to_string()
}

/// The account's change journal, as the JMAP `/changes` reader sees it.
fn destroyed(server: &Harness, account: &str, uid: &str) -> usize {
	let journal = server.data.path().join("accounts").join(account);
	let text = std::fs::read_to_string(journal.join(".jmap_changes")).unwrap_or_default();
	text.lines()
		.filter(|line| line.ends_with(&format!(" E D {uid}")))
		.count()
}

#[tokio::test]
async fn two_sessions_that_delete_the_same_message_destroy_it_once() {
	let server = Harness::start(|s| s).await;
	let (first, second) = (uid(1), uid(2));
	let gone = server.seed("tester", &first, MESSAGE);
	let kept = server.seed("tester", &second, MESSAGE);
	let mut one = server.login("tester", 2).await;
	let mut two = server.login("tester", 2).await;
	for client in [&mut one, &mut two] {
		send(client, b"DELE 1\r\n").await;
		expect(client, "+OK message 1 deleted\r\n").await;
	}
	quit(&mut one).await;
	quit(&mut two).await;
	assert!(!gone.exists());
	assert_eq!(std::fs::read(kept).expect("other message"), MESSAGE);
	assert_eq!(
		destroyed(&server, "tester", &first),
		1,
		"the second QUIT removed nothing, so it must not journal a destruction"
	);
	assert_eq!(destroyed(&server, "tester", &second), 0);
	server.healthy().await;
}

#[tokio::test]
async fn an_old_message_number_never_names_a_message_that_took_its_place() {
	let server = Harness::start(|s| s).await;
	let (first, second, third) = (uid(1), uid(2), uid(3));
	let a = server.seed("tester", &first, MESSAGE);
	let b = server.seed("tester", &second, MESSAGE);
	let mut stale = server.login("tester", 2).await;
	// Another session removes message 1, so number 2 of the stale session is
	// now number 1 of the maildrop, and a new message arrives behind it.
	let mut other = server.login("tester", 2).await;
	send(&mut other, b"DELE 1\r\n").await;
	expect(&mut other, "+OK message 1 deleted\r\n").await;
	quit(&mut other).await;
	assert!(!a.exists());
	let c = server.seed("tester", &third, MESSAGE);
	send(&mut stale, b"DELE 2\r\n").await;
	expect(&mut stale, "+OK message 2 deleted\r\n").await;
	quit(&mut stale).await;
	assert!(
		!b.exists(),
		"the message the stale session named is removed"
	);
	assert_eq!(
		std::fs::read(c).expect("a message that arrived after login"),
		MESSAGE
	);
	assert_eq!(destroyed(&server, "tester", &third), 0);
	let mut fresh = server.login("tester", 1).await;
	send(&mut fresh, b"UIDL 1\r\n").await;
	expect(&mut fresh, &format!("+OK 1 {third}\r\n")).await;
	quit(&mut fresh).await;
	server.healthy().await;
}

#[tokio::test]
async fn rset_keeps_the_message_through_quit_while_another_session_drops_its_deletion() {
	let server = Harness::start(|s| s).await;
	let id = uid(1);
	let path = server.seed("tester", &id, MESSAGE);
	let mut dropped = server.login("tester", 1).await;
	let mut other = server.login("tester", 1).await;
	send(&mut dropped, b"DELE 1\r\n").await;
	expect(&mut dropped, "+OK message 1 deleted\r\n").await;
	send(&mut other, b"DELE 1\r\n").await;
	expect(&mut other, "+OK message 1 deleted\r\n").await;
	send(&mut other, b"RSET\r\n").await;
	expect(&mut other, "+OK 1 messages\r\n").await;
	drop(dropped);
	quit(&mut other).await;
	assert_eq!(std::fs::read(path).expect("uncommitted message"), MESSAGE);
	assert_eq!(destroyed(&server, "tester", &id), 0);
	server.healthy().await;
}

#[tokio::test]
async fn a_message_moved_away_by_another_protocol_is_not_destroyed_by_quit() {
	let server = Harness::start(|s| s).await;
	let id = uid(1);
	let inbox = server.seed("tester", &id, MESSAGE);
	let mut client = server.login("tester", 1).await;
	send(&mut client, b"DELE 1\r\n").await;
	expect(&mut client, "+OK message 1 deleted\r\n").await;
	// An IMAP MOVE lands the file in a folder while the deletion is pending.
	let folder = server
		.data
		.path()
		.join("accounts")
		.join("tester")
		.join("folders")
		.join("Archive")
		.join("new");
	std::fs::create_dir_all(&folder).expect("archive folder");
	let moved = folder.join(format!("{id}.eml"));
	std::fs::rename(&inbox, &moved).expect("move the message");
	quit(&mut client).await;
	assert_eq!(
		std::fs::read(moved).expect("moved message"),
		MESSAGE,
		"QUIT removes from the inbox only and never follows the id into a folder"
	);
	assert_eq!(
		destroyed(&server, "tester", &id),
		0,
		"nothing was destroyed, so nothing is journaled as destroyed"
	);
	server.healthy().await;
}

#[tokio::test]
async fn a_message_destroyed_by_another_protocol_is_unavailable_not_a_crash() {
	let server = Harness::start(|s| s).await;
	let survivor = uid(2);
	let vanished = server.seed("tester", &uid(1), MESSAGE);
	server.seed("tester", &survivor, MESSAGE);
	let mut client = server.login("tester", 2).await;
	std::fs::remove_file(vanished).expect("destroy through another protocol");
	send(&mut client, b"RETR 1\r\n").await;
	let reply = line(&mut client).await.expect("reply").expect("a reply");
	assert!(reply.starts_with("-ERR"), "{reply:?}");
	send(&mut client, b"RETR 2\r\n").await;
	expect(&mut client, &format!("+OK {} octets\r\n", MESSAGE.len())).await;
	for reply in ["Subject: canary\r\n", "\r\n", "body\r\n", ".\r\n"] {
		expect(&mut client, reply).await;
	}
	quit(&mut client).await;
	server.healthy().await;
}
