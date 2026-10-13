//! A scripted remote MX for the queue tests. Each domain answers `RCPT TO`
//! and the end of DATA with the replies its [`Script`] names, and every
//! message the remote accepts is logged with the recipients it went to, so a
//! test can count exactly how many copies each recipient received.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

use super::resolver::{BoxedStream, ConnectFuture, Connection, Connector};

/// How one domain's exchanger answers.
#[derive(Debug, Clone, Default)]
pub struct Script {
	/// Reply to `RCPT TO` per recipient; a recipient not listed gets
	/// `250 2.1.5 ok`.
	pub rcpt: HashMap<String, String>,
	/// Reply at the end of DATA; `None` answers `250 2.0.0 queued`.
	pub data: Option<String>,
}

impl Script {
	/// A script that answers `reply` to `RCPT TO:<recipient>`.
	pub fn rcpt(recipient: &str, reply: &str) -> Self {
		let mut script = Script::default();
		script.rcpt.insert(recipient.to_string(), reply.to_string());
		script
	}
}

/// One message the remote accepted: which exchanger, and for whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
	/// The exchanger host, `mx.<domain>`.
	pub host: String,
	/// The recipients the message was accepted for.
	pub recipients: Vec<String>,
}

/// Connector whose every domain is served by an in-process scripted MX.
#[derive(Clone, Default)]
pub struct FakeRemote {
	scripts: Arc<Mutex<HashMap<String, Script>>>,
	received: Arc<Mutex<Vec<Received>>>,
}

impl FakeRemote {
	/// Set (or replace) how `domain` answers from the next connection on.
	pub fn script(&self, domain: &str, script: Script) {
		self.scripts
			.lock()
			.expect("scripts")
			.insert(domain.to_string(), script);
	}

	/// Every message accepted so far, in order.
	pub fn received(&self) -> Vec<Received> {
		self.received.lock().expect("received").clone()
	}

	/// How many copies `recipient` has received.
	pub fn copies(&self, recipient: &str) -> usize {
		self.received()
			.iter()
			.filter(|message| message.recipients.iter().any(|r| r == recipient))
			.count()
	}
}

impl Connector for FakeRemote {
	fn connect(&self, domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		let script = self
			.scripts
			.lock()
			.expect("scripts")
			.get(domain)
			.cloned()
			.unwrap_or_default();
		let received = self.received.clone();
		let host = format!("mx.{domain}");
		Box::pin(async move {
			let (client, server) = tokio::io::duplex(64 * 1024);
			tokio::spawn(serve(server, host.clone(), script, received));
			Ok(Connection::new(Box::new(client) as BoxedStream, host))
		})
	}
}

/// Speak the server side of one SMTP conversation.
async fn serve(
	stream: DuplexStream,
	host: String,
	script: Script,
	received: Arc<Mutex<Vec<Received>>>,
) {
	let (read, mut write) = tokio::io::split(stream);
	let mut reader = BufReader::new(read);
	let mut accepted: Vec<String> = Vec::new();
	let mut line = String::new();
	if write
		.write_all(format!("220 {host} ready\r\n").as_bytes())
		.await
		.is_err()
	{
		return;
	}
	loop {
		line.clear();
		if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
			return;
		}
		let command = line.trim_end().to_string();
		let upper = command.to_ascii_uppercase();
		let reply = if upper.starts_with("EHLO") {
			format!("250-{host}\r\n250 8BITMIME")
		} else if upper.starts_with("MAIL FROM:") {
			accepted.clear();
			"250 2.1.0 ok".to_string()
		} else if let Some(rest) = upper.strip_prefix("RCPT TO:<") {
			let recipient = command[command.len() - rest.len()..]
				.trim_end_matches('>')
				.to_string();
			let reply = script
				.rcpt
				.get(&recipient)
				.cloned()
				.unwrap_or_else(|| "250 2.1.5 ok".to_string());
			if reply.starts_with('2') {
				accepted.push(recipient);
			}
			reply
		} else if upper == "DATA" {
			if accepted.is_empty() {
				"554 5.5.1 no valid recipients".to_string()
			} else {
				if write.write_all(b"354 go ahead\r\n").await.is_err() {
					return;
				}
				loop {
					line.clear();
					if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
						return;
					}
					if line == ".\r\n" {
						break;
					}
				}
				let reply = script
					.data
					.clone()
					.unwrap_or_else(|| "250 2.0.0 queued".to_string());
				if reply.starts_with('2') {
					received.lock().expect("received").push(Received {
						host: host.clone(),
						recipients: accepted.clone(),
					});
				}
				reply
			}
		} else if upper == "QUIT" {
			let _ = write.write_all(b"221 2.0.0 bye\r\n").await;
			return;
		} else if upper == "RSET" {
			accepted.clear();
			"250 2.0.0 ok".to_string()
		} else {
			"502 5.5.2 command not recognized".to_string()
		};
		if write
			.write_all(format!("{reply}\r\n").as_bytes())
			.await
			.is_err()
		{
			return;
		}
	}
}
