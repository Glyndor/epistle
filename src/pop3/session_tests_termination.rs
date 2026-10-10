use super::command::Command;
use super::session::{Backend, Session};

struct Inbox(Vec<u8>);

impl Backend for Inbox {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		Some("alice".into())
	}
	fn load(&self, _: &str) -> Vec<(String, Vec<u8>)> {
		vec![("message".into(), self.0.clone())]
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

#[test]
fn retr_and_top_terminate_unfinished_lines_on_the_wire() {
	for body in [
		"hello",
		".hello",
		".first\n.last",
		"hello\r\n",
		"hello\r",
		"",
	] {
		let raw = format!("Subject: test\r\n\r\n{body}");
		let mut session = Session::new(Inbox(raw.as_bytes().to_vec()));
		session.handle(Command::User("alice".into()));
		session.handle(Command::Pass(String::new()));
		let stuffed = match body {
			"hello" | "hello\r\n" | "hello\r" => "hello\r\n",
			".hello" => "..hello\r\n",
			".first\n.last" => "..first\r\n..last\r\n",
			_ => "",
		};
		for command in [Command::Retr(1), Command::Top(1, 2)] {
			let status = if matches!(command, Command::Retr(_)) {
				format!("{} octets", raw.len())
			} else {
				"top".into()
			};
			let expected = format!("+OK {status}\r\nSubject: test\r\n\r\n{stuffed}.\r\n");
			assert!(
				session.handle(command).encode() == expected.as_bytes(),
				"RETR and TOP must terminate the final line and preserve dot-stuffing"
			);
		}
	}
}
