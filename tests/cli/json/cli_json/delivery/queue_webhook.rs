//! `queue remove` posts a `canceled` event to the webhook, unless the
//! webhook is switched off: the whole path from the binary's dispatch.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use epistle::smtp::session::AcceptedMessage;
use epistle::storage::FsSpool;

use crate::harness::{Env, env, epistle};

/// A one-shot HTTP receiver on loopback: the request bodies it saw.
fn receiver() -> (String, mpsc::Receiver<String>) {
	let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
	let url = format!("http://{}/hook", listener.local_addr().expect("addr"));
	let (sender, seen) = mpsc::channel();
	std::thread::spawn(move || {
		for stream in listener.incoming() {
			let Ok(mut stream) = stream else { return };
			let mut buffer = vec![0_u8; 8192];
			let mut text = String::new();
			stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
			while let Ok(read) = stream.read(&mut buffer) {
				if read == 0 {
					break;
				}
				text.push_str(&String::from_utf8_lossy(&buffer[..read]));
				if text.contains("\"event\"") {
					break;
				}
			}
			let _ = stream
				.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
			let _ = sender.send(text);
		}
	});
	(url, seen)
}

fn queued(env: &Env) -> uuid::Uuid {
	FsSpool::open(&env.data_dir())
		.expect("spool")
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				..Default::default()
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store")
}

fn remove(env: &Env, id: uuid::Uuid) {
	let output = epistle(
		&[
			"queue",
			"--config",
			&env.config,
			"remove",
			&id.to_string(),
			"--yes",
			"--json",
		],
		b"",
	);
	assert_eq!(
		output.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
}

#[test]
fn an_enabled_webhook_hears_about_a_removed_message() {
	let (url, seen) = receiver();
	let env = env(&format!(
		"[webhook]\nurl = \"{url}\"\nallow_private_webhooks = true\n"
	));
	let id = queued(&env);
	remove(&env, id);
	let body = seen
		.recv_timeout(Duration::from_secs(5))
		.expect("the webhook was not called");
	assert!(body.contains("\"event\":\"canceled\""), "{body}");
	assert!(body.contains(&id.to_string()), "{body}");
}

#[test]
fn a_disabled_webhook_hears_nothing() {
	let (url, seen) = receiver();
	let env = env(&format!("[webhook]\nurl = \"{url}\"\nenabled = false\n"));
	let id = queued(&env);
	remove(&env, id);
	assert!(
		seen.recv_timeout(Duration::from_secs(2)).is_err(),
		"a switched-off webhook was called"
	);
}
