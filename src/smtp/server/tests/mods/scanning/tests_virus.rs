//! The antivirus on SMTP submission: a message an account sends after AUTH
//! is scanned and refused with `554 5.7.1` when it carries a virus; mail
//! from an unauthenticated client is not scanned on this path.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::AsyncWriteExt;

use super::tests_auth::{connector, directory_with_password, reply};
use super::*;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::tests::fake::{FakeClamd, SIGNATURE, eicar};
use crate::antispam::submission_scan::ScanningSink;
use crate::smtp::sink::MemorySink;

/// The routing stand-in, and the sink the server gets: wrapped in the scan
/// when `enabled`.
fn sinks(enabled: bool, clamd: &FakeClamd) -> (Arc<MemorySink>, Arc<dyn MessageSink>) {
	let inner = Arc::new(MemorySink::new());
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()));
	let sink = ScanningSink::wrap(enabled, inner.clone(), Some(hook), None, None).expect("sink");
	(inner, sink)
}

fn message(body: &str) -> String {
	format!("From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: s\r\n\r\n{body}\r\n")
}

/// Submit `data` as alice over STARTTLS and AUTH LOGIN; the reply to the
/// end of DATA.
pub(in crate::smtp::server::tests::mods) async fn submit(
	sink: Arc<dyn MessageSink>,
	data: &str,
) -> String {
	submit_to(
		Server::new("mail.example.org", sink).with_directory(directory_with_password()),
		data,
	)
	.await
}

/// [`submit`] through `server`, which gets the TLS acceptor here.
pub(in crate::smtp::server::tests::mods) async fn submit_to(server: Server, data: &str) -> String {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = server.with_tls(
		crate::tls::ReloadableAcceptor::new(acceptor),
		TlsMode::Opportunistic,
	);
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut client).await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(reply(&mut client).await.starts_with("220 "));
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(name, client)
		.await
		.expect("handshake");
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut tls).await;
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	let password = crate::smtp::auth::tests::base::fixture_password().to_string();
	tls.write_all(format!("{}\r\n", B64.encode(&password)).as_bytes())
		.await
		.expect("pass");
	assert!(reply(&mut tls).await.starts_with("235 "), "auth");
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@elsewhere.example>\r\nDATA\r\n")
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut tls).await);
	}
	tls.write_all(data.as_bytes()).await.expect("data");
	tls.write_all(b".\r\n").await.expect("end");
	let answer = reply(&mut tls).await;
	tls.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut tls).await;
	drop(tls);
	task.await.expect("server task").expect("server result");
	answer
}

#[tokio::test]
async fn an_authenticated_submission_with_a_virus_is_refused() {
	let clamd = FakeClamd::start();
	let (inner, sink) = sinks(true, &clamd);
	let answer = submit(sink, &message(&eicar())).await;
	assert_eq!(
		answer,
		format!("554 5.7.1 message rejected: virus detected ({SIGNATURE})\r\n")
	);
	assert!(inner.messages().is_empty(), "nothing was routed");
}

#[tokio::test]
async fn with_the_scan_off_the_same_submission_is_accepted() {
	let clamd = FakeClamd::start();
	let (inner, sink) = sinks(false, &clamd);
	let answer = submit(sink, &message(&eicar())).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(inner.messages().len(), 1);
	assert_eq!(clamd.scans(), 0);
}

#[tokio::test]
async fn a_clean_authenticated_submission_is_scanned_and_accepted() {
	let clamd = FakeClamd::start();
	let (inner, sink) = sinks(true, &clamd);
	let answer = submit(sink, &message("hello")).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(inner.messages().len(), 1);
	assert_eq!(clamd.scans(), 1);
}

#[tokio::test]
async fn unauthenticated_inbound_mail_is_not_scanned_on_the_submission_path() {
	let clamd = FakeClamd::start();
	let (inner, sink) = sinks(true, &clamd);
	let server = Server::new("mail.example.org", sink).with_directory(directory_with_password());
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(
			b"EHLO c.example.net\r\nMAIL FROM:<x@example.net>\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n",
		)
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut client).await);
	}
	client
		.write_all(format!("{}.\r\n", message(&eicar())).as_bytes())
		.await
		.expect("data");
	let answer = reply(&mut client).await;
	assert!(answer.starts_with("250 "), "{answer}");
	client.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut client).await;
	drop(client);
	task.await.expect("server task").expect("server result");
	assert_eq!(inner.messages().len(), 1);
	assert_eq!(
		clamd.scans(),
		0,
		"inbound screening is the connection loop's job"
	);
}
