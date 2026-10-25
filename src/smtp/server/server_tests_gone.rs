//! A recipient that is gone is answered like a store that is down (a retry
//! later, `451`), and the operator sees it in the log.

use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::layer::SubscriberExt;

use super::*;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::SinkError;

struct Refusing;

impl MessageSink for Refusing {
	fn deliver(&self, _: AcceptedMessage) -> Result<(), SinkError> {
		Err(SinkError::Gone(
			"recipient bob@example.org no longer resolves".into(),
		))
	}
}

#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Lines {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		let mut text = String::new();
		event.record(
			&mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
				use std::fmt::Write;
				let _ = write!(&mut text, "{field}={value:?};");
			},
		);
		self.0.lock().expect("lines").push(text);
	}
}

#[tokio::test]
async fn a_gone_recipient_is_answered_451_and_logged() {
	crate::cli::tracing_capture::keep_callsites_live();
	let lines = Lines::default();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new(
		"mail.example.org",
		Arc::new(Refusing) as Arc<dyn MessageSink>,
	)
	.with_directory(directory);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut read, mut write) = tokio::io::split(client);
	write
		.write_all(
			b"EHLO c.example\r\nMAIL FROM:<a@sender.example>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\nSubject: s\r\n\r\nbody\r\n.\r\nQUIT\r\n",
		)
		.await
		.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("result");
	let output = String::from_utf8(output).expect("ascii");
	assert!(output.contains("451 4.3.0"), "{output}");
	let logged = lines.0.lock().expect("lines").join("\n");
	assert!(logged.contains("delivery failed"), "{logged}");
	assert!(logged.contains("no longer resolves"), "{logged}");
}
