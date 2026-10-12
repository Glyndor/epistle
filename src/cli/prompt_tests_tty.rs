//! Secret reads against a real pseudo-terminal: echo is off while the
//! operator types, back on after every way out of the read, and back on when
//! a signal kills the process in the middle of it.

use std::cell::RefCell;
use std::io::{BufRead, Cursor, Read};

use super::echo::EchoOff;
use super::script::Pty;
use super::{Console, REPEAT, Secret, read_secret};

/// Input that notes, every time it is read, whether the pty echoed.
struct Typed<'a> {
	inner: Cursor<Vec<u8>>,
	pty: &'a Pty,
	echo_seen: RefCell<Vec<bool>>,
	fail: bool,
}

impl<'a> Typed<'a> {
	fn new(pty: &'a Pty, typed: &str) -> Self {
		Typed {
			inner: Cursor::new(typed.as_bytes().to_vec()),
			pty,
			echo_seen: RefCell::new(Vec::new()),
			fail: false,
		}
	}
}

impl Read for Typed<'_> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		self.inner.read(buf)
	}
}

impl BufRead for Typed<'_> {
	fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
		self.echo_seen.borrow_mut().push(self.pty.echo_on());
		if self.fail {
			return Err(std::io::Error::other("terminal went away"));
		}
		self.inner.fill_buf()
	}

	fn consume(&mut self, amount: usize) {
		self.inner.consume(amount);
	}
}

/// Read a secret from `typed` on `pty`; returns the outcome, stderr, and
/// the echo state seen at each read.
fn read_on(
	pty: &Pty,
	interactive: bool,
	typed: &mut Typed<'_>,
	twice: bool,
) -> (Secret, String, Vec<bool>) {
	let mut err = Vec::new();
	let secret = read_secret(
		&mut Console {
			interactive,
			tty: Some(pty.slave),
			input: typed,
			err: &mut err,
		},
		"Password for \"alice\"",
		twice,
	);
	let seen = typed.echo_seen.take();
	(secret, String::from_utf8(err).expect("utf-8"), seen)
}

fn asked_twice() -> String {
	format!("Password for \"alice\": \n{REPEAT}: \n")
}

#[test]
fn matching_passwords_are_read_with_echo_off_and_echo_comes_back() {
	let pty = Pty::open();
	let mut typed = Typed::new(&pty, "correct horse\ncorrect horse\n");
	let (secret, err, seen) = read_on(&pty, true, &mut typed, true);
	assert_eq!(secret, Secret::Read("correct horse".to_string()));
	assert_eq!(err, asked_twice(), "each question, then a newline per read");
	assert!(
		!seen.is_empty() && seen.iter().all(|on| !on),
		"echo seen: {seen:?}"
	);
	assert!(pty.echo_on(), "echo is restored after a match");
}

#[test]
fn a_mismatch_is_refused_and_echo_comes_back() {
	let pty = Pty::open();
	let mut typed = Typed::new(&pty, "correct horse\ncorrect h0rse\n");
	let (secret, err, seen) = read_on(&pty, true, &mut typed, true);
	assert_eq!(secret, Secret::Mismatch);
	assert_eq!(err, asked_twice());
	assert!(seen.iter().all(|on| !on), "echo seen: {seen:?}");
	assert!(pty.echo_on(), "echo is restored after a mismatch");
}

#[test]
fn end_of_input_at_either_question_restores_echo() {
	let pty = Pty::open();
	let mut typed = Typed::new(&pty, "");
	let (secret, err, _) = read_on(&pty, true, &mut typed, true);
	assert_eq!(secret, Secret::Eof);
	assert_eq!(err, "Password for \"alice\": \n");
	assert!(
		pty.echo_on(),
		"echo is restored after EOF at the first read"
	);

	let mut typed = Typed::new(&pty, "correct horse\n");
	let (secret, err, _) = read_on(&pty, true, &mut typed, true);
	assert_eq!(secret, Secret::Eof);
	assert_eq!(err, asked_twice());
	assert!(
		pty.echo_on(),
		"echo is restored after EOF at the second read"
	);
}

#[test]
fn a_blank_line_or_a_read_error_restores_echo() {
	let pty = Pty::open();
	let mut typed = Typed::new(&pty, "\n");
	let (secret, _, _) = read_on(&pty, true, &mut typed, false);
	assert_eq!(secret, Secret::Blank);
	assert!(pty.echo_on(), "echo is restored after a blank line");

	let mut typed = Typed::new(&pty, "correct horse\n");
	typed.fail = true;
	let (secret, _, _) = read_on(&pty, true, &mut typed, false);
	assert_eq!(secret, Secret::Failed("terminal went away".to_string()));
	assert!(pty.echo_on(), "echo is restored after a read error");
}

#[test]
fn a_terminal_on_stdin_hides_the_secret_even_when_stderr_is_redirected() {
	// stdin is a terminal but stderr is not: nothing is asked, one line is
	// read, and still nothing typed is echoed.
	let pty = Pty::open();
	let mut typed = Typed::new(&pty, "correct horse\nsecond\n");
	let (secret, err, seen) = read_on(&pty, false, &mut typed, true);
	assert_eq!(secret, Secret::Read("correct horse".to_string()));
	assert_eq!(err, "");
	assert!(
		!seen.is_empty() && seen.iter().all(|on| !on),
		"echo seen: {seen:?}"
	);
	assert!(pty.echo_on());
}

#[test]
fn the_guard_puts_the_previous_signal_handlers_back() {
	let pty = Pty::open();
	let before = handler(libc::SIGTERM);
	let guard = EchoOff::new(pty.slave).expect("echo off");
	assert_ne!(
		handler(libc::SIGTERM),
		before,
		"the guard installs its handler"
	);
	assert!(
		EchoOff::new(pty.slave).is_err(),
		"a second guard is refused while one is alive"
	);
	drop(guard);
	assert_eq!(
		handler(libc::SIGTERM),
		before,
		"the previous SIGTERM handler is back"
	);
	assert!(pty.echo_on());
}

fn handler(signal: libc::c_int) -> libc::sighandler_t {
	// SAFETY: a null new action only queries the current one.
	unsafe {
		let mut current: libc::sigaction = std::mem::zeroed();
		libc::sigaction(signal, std::ptr::null(), &mut current);
		current.sa_sigaction
	}
}

#[test]
fn ctrl_c_in_the_middle_of_a_secret_read_restores_echo_before_the_process_dies() {
	let pty = Pty::open();
	// SAFETY: the child only makes system calls and leaves with `_exit`, so
	// it never runs the test harness's code or destructors.
	let pid = unsafe { libc::fork() };
	assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
	if pid == 0 {
		let code = unsafe {
			libc::signal(libc::SIGINT, libc::SIG_DFL);
			match EchoOff::new(pty.slave) {
				Err(_) => 3,
				Ok(guard) if pty.echo_on() => {
					drop(guard);
					4
				}
				Ok(guard) => {
					libc::raise(libc::SIGINT);
					std::mem::forget(guard);
					5
				}
			}
		};
		unsafe { libc::_exit(code) };
	}
	let mut status = 0;
	// SAFETY: `pid` is our child; `status` is a valid out pointer.
	let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
	assert_eq!(waited, pid);
	assert!(
		libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGINT,
		"the child must die of SIGINT, not exit (status {status:#x})"
	);
	assert!(pty.echo_on(), "SIGINT left the terminal without echo");
}
