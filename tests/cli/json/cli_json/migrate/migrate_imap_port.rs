//! `epistle migrate imap --port`: the connection goes to the port given, and
//! a port that is not one is refused before anything connects.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::harness::{add_account, env, epistle};

/// Run `migrate imap` against `127.0.0.1:<port>` in plaintext, the password
/// on stdin, with `extra` after the fixed flags.
fn imap(config: &str, port: &str, extra: &[&str]) -> std::process::Output {
	let mut args = vec![
		"migrate",
		"--config",
		config,
		"imap",
		"--account",
		"alice",
		"--host",
		"127.0.0.1",
		"--port",
		port,
		"--user",
		"remote",
		"--insecure-plaintext",
	];
	args.extend_from_slice(extra);
	epistle(&args, b"remote-password\n")
}

#[test]
fn the_connection_goes_to_the_port_given() {
	let env = env("");
	add_account(&env, "alice");
	let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
	let port = listener.local_addr().expect("address").port();
	let finished = Arc::new(AtomicBool::new(false));
	let seen = {
		let finished = Arc::clone(&finished);
		std::thread::spawn(move || {
			// The first connection ends the run: it is closed without a
			// word, so the command gives up on the greeting. Whether the
			// command was the one to connect is read while the connection is
			// still open, so that the command cannot end, and the test say
			// so, before the answer is taken.
			let (stream, _) = listener.accept().expect("accept");
			let from_the_command = !finished.load(Ordering::SeqCst);
			drop(stream);
			from_the_command
		})
	};

	let output = imap(&env.config, &port.to_string(), &["--dry-run"]);

	// A command that never connected leaves the thread waiting: connect
	// here, after saying the command is over, to let it go.
	finished.store(true, Ordering::SeqCst);
	let _ = TcpStream::connect(("127.0.0.1", port));
	assert!(
		seen.join().expect("listener thread"),
		"the command did not connect to the port it was given"
	);
	// The listener never speaks IMAP, so the run does not succeed.
	assert_ne!(output.status.code(), Some(0));
	assert!(
		output.status.code().is_some(),
		"the command ended on its own"
	);
}

#[test]
fn a_port_that_is_not_one_is_a_usage_error() {
	let env = env("");
	add_account(&env, "alice");
	for port in ["65536", "http", ""] {
		let output = imap(&env.config, port, &[]);
		assert_eq!(output.status.code(), Some(2), "{port:?}");
		assert!(output.stdout.is_empty(), "{port:?}");
		let message = String::from_utf8_lossy(&output.stderr);
		assert!(message.contains("--port"), "{port:?}: {message}");
	}
}

#[test]
fn nothing_listening_on_the_port_is_a_failure_that_is_explained() {
	let env = env("");
	add_account(&env, "alice");
	// Bind and drop: the port was free a moment ago and nothing takes it.
	let port = {
		let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
		listener.local_addr().expect("address").port().to_string()
	};
	let output = imap(&env.config, &port, &["--dry-run"]);
	assert_ne!(output.status.code(), Some(0));
	assert!(!output.stderr.is_empty(), "the failure is explained");
}
