//! The antispam scopes on the wire: the sender lists at `RCPT TO` and
//! after authentication, and the attachment settings of the recipients.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::antispam::scopes::Scopes;
use crate::dkim::test_support::KeyDns;
use crate::smtp::directory::Directory;
use crate::smtp::server::{DirectoryHandle, MessageSink, Server};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MemorySink;

mod attachments;
mod checks;
mod favoured;
mod refusals;
mod thresholds;

/// A scorer that finds every message spam, with a corpus it trusts.
struct SpamScorer;

impl crate::antispam::corpus::BayesScorer for SpamScorer {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		Box::pin(async { Ok(0.99) })
	}
	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		Box::pin(async { Some(0.99) })
	}
	fn is_trusted<'a>(
		&'a self,
		_scope: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
		Box::pin(async { true })
	}
}

/// What a conversation produced.
pub(super) struct Run {
	/// Everything the server said.
	pub output: String,
	/// What reached the sink.
	pub messages: Vec<AcceptedMessage>,
}

/// The scopes of a configuration with the example domains and `extra`.
pub(super) fn scopes(extra: &str) -> Arc<Scopes> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.com\"]\n{extra}"
	)
	.expect("write config");
	let config = crate::config::Config::load(file.path()).expect("config loads");
	Arc::new(Scopes::from_config(&config))
}

/// A server for `example.org` (alice and bob) and `example.com` (carol).
pub(super) fn server(sink: &Arc<MemorySink>, scopes: Option<Arc<Scopes>>) -> Server {
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string(), "example.com".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("carol@example.com".to_string(), "carol".to_string()),
		],
	));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory);
	match scopes {
		Some(scopes) => server.with_scopes(scopes),
		None => server,
	}
}

/// Run `script` against `server` from 192.0.2.7.
pub(super) async fn run(server: Server, sink: &Arc<MemorySink>, script: &str) -> Run {
	let (client, server_stream) = tokio::io::duplex(256 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	Run {
		output: String::from_utf8_lossy(&output).into_owned(),
		messages: sink.messages(),
	}
}

/// DNS with `records` as TXT answers.
pub(super) fn dns(records: &[(&str, &str)]) -> Arc<KeyDns> {
	Arc::new(KeyDns(
		records
			.iter()
			.map(|(name, text)| (name.to_string(), vec![text.to_string()]))
			.collect::<HashMap<_, _>>(),
	))
}

/// A plain message body from `from` to bob.
pub(super) fn plain(from: &str) -> String {
	format!("From: {from}\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nhello\r\n")
}

/// The script of one message from `envelope` to `recipients`.
pub(super) fn script(envelope: &str, recipients: &[&str], data: &str) -> String {
	let mut script = format!("EHLO client.example.org\r\nMAIL FROM:<{envelope}>\r\n");
	for recipient in recipients {
		script.push_str(&format!("RCPT TO:<{recipient}>\r\n"));
	}
	script.push_str(&format!("DATA\r\n{data}.\r\nQUIT\r\n"));
	script
}
