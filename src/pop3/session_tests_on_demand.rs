//! A session reads an index at sign-in and one message at a time after that.

use std::cell::RefCell;
use std::rc::Rc;

use super::bounds::{MAX_MESSAGE_OCTETS, MAX_SESSION_MESSAGES};
use super::command::Command;
use super::session::{Backend, Response, Session};

struct Counting {
	index: Vec<(String, usize)>,
	body: Vec<u8>,
	fetched: Rc<RefCell<Vec<String>>>,
}

impl Backend for Counting {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		Some("alice".into())
	}
	fn list(&self, _: &str) -> Vec<(String, usize)> {
		self.index.clone()
	}
	fn fetch(&self, _: &str, uid: &str) -> Option<Vec<u8>> {
		self.fetched.borrow_mut().push(uid.to_string());
		Some(self.body.clone())
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

fn session_over(
	index: Vec<(String, usize)>,
	body: &[u8],
) -> (Session<Counting>, Rc<RefCell<Vec<String>>>) {
	let fetched = Rc::new(RefCell::new(Vec::new()));
	let mut session = Session::new(Counting {
		index,
		body: body.to_vec(),
		fetched: fetched.clone(),
	});
	session.handle(Command::User("alice".into()));
	session.handle(Command::Pass(String::new()));
	(session, fetched)
}

fn three() -> Vec<(String, usize)> {
	vec![("a".into(), 5), ("b".into(), 7), ("c".into(), 9)]
}

#[test]
fn listing_commands_read_no_message() {
	let (mut session, fetched) = session_over(three(), b"x");
	assert_eq!(
		session.handle(Command::Stat),
		Response::Ok("3 21".to_string())
	);
	session.handle(Command::List(None));
	session.handle(Command::List(Some(2)));
	session.handle(Command::Uidl(None));
	session.handle(Command::Uidl(Some(3)));
	session.handle(Command::Dele(1));
	session.handle(Command::Quit);
	assert!(fetched.borrow().is_empty(), "{:?}", fetched.borrow());
}

#[test]
fn list_reports_the_size_of_the_index() {
	let (mut session, _) = session_over(three(), b"x");
	assert_eq!(
		session.handle(Command::List(Some(2))),
		Response::Ok("2 7".to_string())
	);
}

#[test]
fn retr_and_top_read_only_the_message_asked_for() {
	let (mut session, fetched) = session_over(three(), b"Subject: s\r\n\r\nbody\r\n");
	assert!(matches!(
		session.handle(Command::Retr(2)),
		Response::Multiline { .. }
	));
	assert!(matches!(
		session.handle(Command::Top(3, 1)),
		Response::Multiline { .. }
	));
	assert_eq!(*fetched.borrow(), vec!["b".to_string(), "c".to_string()]);
}

#[test]
fn a_deleted_message_is_not_read() {
	let (mut session, fetched) = session_over(three(), b"x");
	session.handle(Command::Dele(1));
	assert!(matches!(session.handle(Command::Retr(1)), Response::Err(_)));
	assert!(fetched.borrow().is_empty());
}

#[test]
fn a_message_over_the_cap_is_refused() {
	let body = vec![b'x'; MAX_MESSAGE_OCTETS + 1];
	let (mut session, _) = session_over(vec![("big".into(), body.len())], &body);
	assert!(matches!(session.handle(Command::Retr(1)), Response::Err(_)));
	assert!(matches!(
		session.handle(Command::Top(1, 0)),
		Response::Err(_)
	));
}

#[test]
fn an_inbox_larger_than_the_cap_lists_the_newest() {
	let index: Vec<(String, usize)> = (0..MAX_SESSION_MESSAGES + 5)
		.map(|n| (n.to_string(), 1))
		.collect();
	let (mut session, _) = session_over(index, b"x");
	assert_eq!(
		session.handle(Command::Stat),
		Response::Ok(format!("{MAX_SESSION_MESSAGES} {MAX_SESSION_MESSAGES}"))
	);
	// The five oldest are the ones left out.
	assert_eq!(
		session.handle(Command::Uidl(Some(1))),
		Response::Ok("1 5".to_string())
	);
	assert_eq!(
		session.handle(Command::Uidl(Some(MAX_SESSION_MESSAGES as u32))),
		Response::Ok(format!(
			"{MAX_SESSION_MESSAGES} {}",
			MAX_SESSION_MESSAGES + 4
		))
	);
}

#[test]
fn an_unreadable_message_is_a_permanent_condition_and_not_a_client_error() {
	struct Gone;
	impl Backend for Gone {
		fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
			Some("alice".into())
		}
		fn list(&self, _: &str) -> Vec<(String, usize)> {
			vec![("m".into(), 3)]
		}
		fn fetch(&self, _: &str, _: &str) -> Option<Vec<u8>> {
			None
		}
		fn remove(&self, _: &str, _: &[String]) {}
	}
	let mut session = Session::new(Gone);
	session.handle(Command::User("alice".into()));
	session.handle(Command::Pass(String::new()));
	let reply = session.handle(Command::Retr(1));
	assert_eq!(
		reply,
		Response::Err("[SYS/PERM] message unavailable".to_string())
	);
	assert!(!reply.is_client_error());
	assert!(session.handle(Command::Retr(9)).is_client_error());
}
