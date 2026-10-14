//! A scripted remote MX for the queue tests. Each domain answers `RCPT TO`
//! and the end of DATA with the replies its [`Script`] names, and every
//! message the remote accepts is logged with the recipients it went to, so a
//! test can count exactly how many copies each recipient received.
//!
//! A domain can also have several exchangers, each with its own script, and
//! a script can stop answering at a chosen step ([`Hang`]) to model a server
//! that accepts the connection and then says nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

use super::resolver::{BoxedStream, ConnectFuture, Connection, Connector};

/// The step at which a scripted exchanger stops answering, keeping the
/// connection open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hang {
	/// Never sends the greeting.
	Greeting,
	/// Never answers EHLO.
	Ehlo,
	/// Answers STARTTLS with 220, then never starts the handshake.
	TlsHandshake,
	/// Never answers MAIL.
	Mail,
	/// Never answers RCPT.
	Rcpt,
	/// Never answers DATA.
	DataInit,
	/// Answers DATA with 354, then stops reading the message.
	DataBody,
	/// Reads the whole message, then never answers the final dot.
	DataEnd,
	/// Delivers, then never answers QUIT.
	Quit,
}

/// How one domain's exchanger answers.
#[derive(Debug, Clone, Default)]
pub struct Script {
	/// Reply to `RCPT TO` per recipient; a recipient not listed gets
	/// `250 2.1.5 ok`.
	pub rcpt: HashMap<String, String>,
	/// Reply at the end of DATA; `None` answers `250 2.0.0 queued`.
	pub data: Option<String>,
	/// The greeting; `None` answers `220 <host> ready`.
	pub greeting: Option<String>,
	/// Reply to MAIL; `None` answers `250 2.1.0 ok`.
	pub mail: Option<String>,
	/// After how many accepted recipients every further RCPT gets
	/// `452 4.5.3 too many recipients`.
	pub max_recipients: Option<usize>,
	/// Offer STARTTLS. Without [`Hang::TlsHandshake`], the handshake then
	/// fails: the exchanger answers 220 and sends bytes that are not TLS.
	pub starttls: bool,
	/// Where the exchanger stops answering.
	pub hang: Option<Hang>,
	/// How long the exchanger takes to answer the final dot.
	pub delay: Option<std::time::Duration>,
}

impl Script {
	/// A script that answers `reply` to `RCPT TO:<recipient>`.
	pub fn rcpt(recipient: &str, reply: &str) -> Self {
		let mut script = Script::default();
		script.rcpt.insert(recipient.to_string(), reply.to_string());
		script
	}

	/// A script that stops answering at `hang`.
	pub fn hang(hang: Hang) -> Self {
		Script {
			hang: Some(hang),
			starttls: hang == Hang::TlsHandshake,
			..Script::default()
		}
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

/// Connections opened and running, per exchanger domain.
#[derive(Debug, Default)]
struct Load {
	opened: HashMap<String, usize>,
	active: HashMap<String, usize>,
	most: HashMap<String, usize>,
	active_total: usize,
	most_total: usize,
}

/// The exchangers of each domain, in preference order, with their scripts.
type Exchangers = HashMap<String, Vec<(String, Script)>>;

/// Connector whose every domain is served by in-process scripted MXs.
#[derive(Clone, Default)]
pub struct FakeRemote {
	scripts: Arc<Mutex<Exchangers>>,
	received: Arc<Mutex<Vec<Received>>>,
	received_at: Arc<Mutex<Vec<(String, tokio::time::Instant)>>>,
	messages: Arc<Mutex<Vec<String>>>,
	load: Arc<Mutex<Load>>,
}

#[allow(dead_code)]
impl FakeRemote {
	/// Set (or replace) how `domain` answers from the next connection on,
	/// with one exchanger, `mx.<domain>`.
	pub fn script(&self, domain: &str, script: Script) {
		self.scripts
			.lock()
			.expect("scripts")
			.insert(domain.to_string(), vec![(format!("mx.{domain}"), script)]);
	}

	/// Give `domain` one exchanger per script, `mx1.<domain>`, `mx2.<domain>`
	/// and so on, in preference order.
	pub fn exchangers(&self, domain: &str, scripts: Vec<Script>) {
		let hosts = scripts
			.into_iter()
			.enumerate()
			.map(|(index, script)| (format!("mx{}.{domain}", index + 1), script))
			.collect();
		self.scripts
			.lock()
			.expect("scripts")
			.insert(domain.to_string(), hosts);
	}

	/// Every message accepted so far, in order.
	pub fn received(&self) -> Vec<Received> {
		self.received.lock().expect("received").clone()
	}

	/// The full text of every message accepted so far, in order.
	pub fn messages(&self) -> Vec<String> {
		self.messages.lock().expect("messages").clone()
	}

	/// How many copies `recipient` has received.
	pub fn copies(&self, recipient: &str) -> usize {
		self.received()
			.iter()
			.filter(|message| message.recipients.iter().any(|r| r == recipient))
			.count()
	}

	/// When `recipient` first got a copy, on the tokio clock.
	pub fn delivered_at(&self, recipient: &str) -> Option<tokio::time::Instant> {
		self.received_at
			.lock()
			.expect("received_at")
			.iter()
			.find(|(r, _)| r == recipient)
			.map(|(_, at)| *at)
	}

	/// Connections opened to `host` so far.
	pub fn connections(&self, host: &str) -> usize {
		let load = self.load.lock().expect("load");
		load.opened.get(host).copied().unwrap_or(0)
	}

	/// The most connections to the exchangers of `domain` open at once.
	pub fn most_at_once(&self, domain: &str) -> usize {
		let load = self.load.lock().expect("load");
		load.most.get(domain).copied().unwrap_or(0)
	}

	/// The most connections open at once, all domains together.
	pub fn most_at_once_total(&self) -> usize {
		self.load.lock().expect("load").most_total
	}

	/// The exchanger of `domain` to try after the hosts in `tried`.
	fn next_exchanger(&self, domain: &str, tried: &[String]) -> Option<(String, Script)> {
		let scripts = self.scripts.lock().expect("scripts");
		match scripts.get(domain) {
			Some(hosts) => hosts
				.iter()
				.find(|(host, _)| !tried.contains(host))
				.cloned(),
			None if tried.is_empty() => Some((format!("mx.{domain}"), Script::default())),
			None => None,
		}
	}
}

/// Counts one open connection while it lives.
struct Open {
	load: Arc<Mutex<Load>>,
	domain: String,
}

impl Open {
	fn new(load: Arc<Mutex<Load>>, domain: &str, host: &str) -> Self {
		{
			let mut counts = load.lock().expect("load");
			*counts.opened.entry(host.to_string()).or_default() += 1;
			let active = counts.active.entry(domain.to_string()).or_default();
			*active += 1;
			let active = *active;
			let most = counts.most.entry(domain.to_string()).or_default();
			*most = (*most).max(active);
			counts.active_total += 1;
			counts.most_total = counts.most_total.max(counts.active_total);
		}
		Open {
			load,
			domain: domain.to_string(),
		}
	}
}

impl Drop for Open {
	fn drop(&mut self) {
		if let Ok(mut counts) = self.load.lock() {
			if let Some(active) = counts.active.get_mut(&self.domain) {
				*active = active.saturating_sub(1);
			}
			counts.active_total = counts.active_total.saturating_sub(1);
		}
	}
}

impl Connector for FakeRemote {
	fn connect(&self, domain: &str, policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		self.connect_skipping(domain, policy, &[])
	}

	fn connect_skipping(
		&self,
		domain: &str,
		_policy: Option<&crate::mtasts::Policy>,
		tried: &[String],
	) -> ConnectFuture<'_> {
		let next = self.next_exchanger(domain, tried);
		let domain = domain.to_string();
		let remote = self.clone();
		Box::pin(async move {
			let Some((host, script)) = next else {
				return Err(super::client::DeliveryError::Transient(format!(
					"no further exchanger for {domain}"
				)));
			};
			let (client, server) = tokio::io::duplex(64 * 1024);
			let open = Open::new(remote.load.clone(), &domain, &host);
			tokio::spawn(serve(server, host.clone(), script, remote, open));
			Ok(Connection::new(Box::new(client) as BoxedStream, host))
		})
	}
}

/// Wait forever, keeping whatever the caller holds alive.
async fn stall() {
	std::future::pending::<()>().await;
}

/// Speak the server side of one SMTP conversation.
async fn serve(
	stream: DuplexStream,
	host: String,
	script: Script,
	remote: FakeRemote,
	_open: Open,
) {
	let (read, mut write) = tokio::io::split(stream);
	let mut reader = BufReader::new(read);
	let mut accepted: Vec<String> = Vec::new();
	let mut line = String::new();
	if script.hang == Some(Hang::Greeting) {
		return stall().await;
	}
	let greeting = script
		.greeting
		.clone()
		.unwrap_or_else(|| format!("220 {host} ready"));
	if write
		.write_all(format!("{greeting}\r\n").as_bytes())
		.await
		.is_err()
		|| !greeting.starts_with("220")
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
		let hang_on = |step: Hang| script.hang == Some(step);
		let reply = if upper.starts_with("EHLO") {
			if hang_on(Hang::Ehlo) {
				return stall().await;
			}
			match script.starttls {
				true => format!("250-{host}\r\n250-STARTTLS\r\n250 8BITMIME"),
				false => format!("250-{host}\r\n250 8BITMIME"),
			}
		} else if upper == "STARTTLS" && script.starttls {
			let _ = write.write_all(b"220 2.0.0 go ahead\r\n").await;
			if hang_on(Hang::TlsHandshake) {
				return stall().await;
			}
			let _ = write.write_all(b"this is not a TLS record\r\n").await;
			return;
		} else if upper.starts_with("MAIL FROM:") {
			if hang_on(Hang::Mail) {
				return stall().await;
			}
			accepted.clear();
			script
				.mail
				.clone()
				.unwrap_or_else(|| "250 2.1.0 ok".to_string())
		} else if let Some(rest) = upper.strip_prefix("RCPT TO:<") {
			if hang_on(Hang::Rcpt) {
				return stall().await;
			}
			let recipient = command[command.len() - rest.len()..]
				.trim_end_matches('>')
				.to_string();
			let full = script
				.max_recipients
				.is_some_and(|max| accepted.len() >= max);
			let reply = match full {
				true => "452 4.5.3 too many recipients".to_string(),
				false => script
					.rcpt
					.get(&recipient)
					.cloned()
					.unwrap_or_else(|| "250 2.1.5 ok".to_string()),
			};
			if reply.starts_with('2') {
				accepted.push(recipient);
			}
			reply
		} else if upper == "DATA" {
			if hang_on(Hang::DataInit) {
				return stall().await;
			}
			if accepted.is_empty() {
				"554 5.5.1 no valid recipients".to_string()
			} else {
				if write.write_all(b"354 go ahead\r\n").await.is_err() {
					return;
				}
				if hang_on(Hang::DataBody) {
					return stall().await;
				}
				let mut message = String::new();
				loop {
					line.clear();
					if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
						return;
					}
					if line == ".\r\n" {
						break;
					}
					message.push_str(&line);
				}
				if hang_on(Hang::DataEnd) {
					return stall().await;
				}
				if let Some(delay) = script.delay {
					tokio::time::sleep(delay).await;
				}
				let reply = script
					.data
					.clone()
					.unwrap_or_else(|| "250 2.0.0 queued".to_string());
				if reply.starts_with('2') {
					remote.record(&host, &accepted, message);
				}
				reply
			}
		} else if upper == "QUIT" {
			if hang_on(Hang::Quit) {
				return stall().await;
			}
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

impl FakeRemote {
	/// Log one accepted message.
	fn record(&self, host: &str, recipients: &[String], message: String) {
		let now = tokio::time::Instant::now();
		self.received.lock().expect("received").push(Received {
			host: host.to_string(),
			recipients: recipients.to_vec(),
		});
		self.received_at
			.lock()
			.expect("received_at")
			.extend(recipients.iter().map(|r| (r.clone(), now)));
		self.messages.lock().expect("messages").push(message);
	}
}
