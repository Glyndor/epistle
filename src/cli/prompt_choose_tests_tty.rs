//! The picker against a real pseudo-terminal: the operator types the number
//! on the terminal and the line discipline hands it over.

use std::io::BufReader;
use std::os::fd::FromRawFd;

use super::Console;
use super::choose::choose;
use super::script::Pty;

#[test]
fn a_number_typed_on_a_pty_picks_the_entry() {
	let pty = Pty::open();
	pty.type_in("2\n");
	// SAFETY: dup returns a fresh descriptor the File then owns.
	let slave = unsafe { std::fs::File::from_raw_fd(libc::dup(pty.slave)) };
	let mut input = BufReader::new(slave);
	let mut err = Vec::new();
	let picked = choose(
		&mut Console {
			interactive: true,
			tty: Some(pty.slave),
			input: &mut input,
			err: &mut err,
		},
		"domain",
		&["example.org".to_string(), "example.net".to_string()],
	);
	assert_eq!(picked.as_deref(), Some("example.net"));
	let err = String::from_utf8(err).expect("utf-8");
	assert!(
		err.starts_with("Pick a domain:\n  1) example.org\n"),
		"{err}"
	);
	assert!(pty.echo_on(), "the picker leaves echo as it found it");
}
