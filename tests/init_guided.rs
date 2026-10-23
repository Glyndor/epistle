//! Guided setup through the shipped binary, including confirmation and SIGINT.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "init_guided/descriptors.rs"]
mod descriptors;

#[path = "init_guided/copies.rs"]
mod copies;

/// The whole budget one guided run may take.
const DEADLINE: Duration = Duration::from_secs(120);

/// How much longer the master is read once the child is gone. The child
/// exiting does not close the terminal while another process still holds its
/// slave open, and that process is nobody this test can wait for.
const DRAIN: Duration = Duration::from_secs(10);

/// This test, by name, for the copies it starts. Each copy skips it so a copy
/// never starts copies of its own.
const SELF: &str = "the_target_passes_with_several_copies_at_once";

/// The two ends of a pseudo-terminal, both closed across `exec`.
///
/// The tests of this target run in parallel threads, and each one spawns
/// `epistle init` while the others still hold their own pair open. An
/// inheritable descriptor is inherited by whichever child the next test spawns,
/// and that child then holds the slave of a terminal whose master is waiting
/// for the end of its stream: the end never arrives, the owner waits out its
/// deadline, and the two tests wait on each other for good.
///
/// So each end is asked for with `O_CLOEXEC` in the call that creates it, which
/// is the only shape with no window in it: `openpty` leaves both descriptors
/// inheritable, and a `fcntl` after it lands while another thread may already
/// have forked a child, which keeps that child's copy of the table with the old
/// flags. `Command` puts the slave on the child's standard descriptors with
/// `dup2`, and `dup2` clears the flag on the new descriptor, so the child still
/// reads from the terminal.
fn pseudo_terminal() -> (File, File) {
	// SAFETY: posix_openpt takes only the flags to open the master with, so no
	// pointer of ours is left to read after it returns.
	let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
	assert!(
		master >= 0,
		"posix_openpt: {}",
		std::io::Error::last_os_error()
	);
	// SAFETY: both calls take the master descriptor this function owns.
	unsafe {
		assert_eq!(libc::grantpt(master), 0, "grantpt");
		assert_eq!(libc::unlockpt(master), 0, "unlockpt");
	}
	let mut name = [0 as libc::c_char; 256];
	assert_eq!(
		// SAFETY: ptsname_r writes a NUL-terminated path into `name` and reads
		// nothing else.
		unsafe { libc::ptsname_r(master, name.as_mut_ptr(), name.len()) },
		0,
		"ptsname_r: {}",
		std::io::Error::last_os_error()
	);
	// SAFETY: ptsname_r returned 0, so `name` holds the path in the operating
	// system's own buffer, and these flags ask for a private terminal that
	// closes across `exec`.
	let slave = unsafe {
		libc::open(
			name.as_ptr(),
			libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
		)
	};
	assert!(
		slave >= 0,
		"open the pseudo-terminal slave: {}",
		std::io::Error::last_os_error()
	);
	// SAFETY: both calls returned fresh descriptors, and these two File values
	// are their only owners from here on.
	(unsafe { File::from_raw_fd(master) }, unsafe {
		File::from_raw_fd(slave)
	})
}

/// Start `epistle init` on its own pseudo-terminal. `root` holds the state
/// directory, so no run reads or writes the draft of another one.
fn spawn_on_terminal(root: &Path, colour: bool) -> (File, Child) {
	let (master, slave) = pseudo_terminal();
	let mut command = Command::new(env!("CARGO_BIN_EXE_epistle"));
	command
		.arg("init")
		.env("XDG_STATE_HOME", root.join("state"))
		.env_remove("NO_COLOR")
		.env_remove("TERM");
	if !colour {
		command.env("NO_COLOR", "1").env("TERM", "dumb");
	}
	command
		.stdin(slave.try_clone().unwrap())
		.stdout(Stdio::piped())
		.stderr(slave);
	// An ignored disposition survives `exec`. A background job of a shell, a
	// service manager and a container runtime all start a process with SIGINT
	// ignored, and that process would hand `epistle init` a Ctrl-C that stops
	// nothing, so the guided setup would wait out its deadline. The child
	// starts from the default disposition, which is what a terminal session
	// gives it, and the two tests that interrupt a run expect that.
	// SAFETY: the closure runs between `fork` and `exec`, where the only work
	// allowed is async-signal-safe. It calls `signal` and returns.
	unsafe {
		command.pre_exec(|| {
			libc::signal(libc::SIGINT, libc::SIG_DFL);
			Ok(())
		});
	}
	let child = command.spawn().expect("spawn epistle init");
	(master, child)
}

/// Whether the child is gone and the master has been waiting for the end of
/// its stream for [`DRAIN`], which means nobody this test owns is going to
/// close the terminal. `since` carries the moment the child was first seen
/// gone, so the caller only starts counting once.
fn orphaned_terminal(child: &mut Child, since: &mut Option<Instant>) -> bool {
	if since.is_none() && child.try_wait().expect("child status").is_some() {
		*since = Some(Instant::now());
	}
	since.is_some_and(|gone| gone.elapsed() > DRAIN)
}

fn terminal(root: &Path, input: &str, interrupt: bool, colour: bool) -> (ExitStatus, String) {
	let (mut master, mut child) = spawn_on_terminal(root, colour);
	master.write_all(input.as_bytes()).unwrap();
	let deadline = Instant::now() + DEADLINE;
	let mut gone = None;
	let mut screen = Vec::new();
	let mut signalled = false;
	loop {
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			panic!("guided setup did not finish before its test deadline");
		}
		if orphaned_terminal(&mut child, &mut gone) {
			panic!(
				"the pseudo-terminal stayed open after epistle init exited, so a process outside this test holds it"
			);
		}
		let mut poll = libc::pollfd {
			fd: master.as_raw_fd(),
			events: libc::POLLIN,
			revents: 0,
		};
		// SAFETY: poll points to one live descriptor record.
		let ready = unsafe { libc::poll(&mut poll, 1, 100) };
		assert!(ready >= 0);
		if ready > 0 {
			let mut buffer = [0u8; 4096];
			match master.read(&mut buffer) {
				Ok(0) | Err(_) => break,
				Ok(n) => screen.extend_from_slice(&buffer[..n]),
			}
		}
		if interrupt && !signalled && String::from_utf8_lossy(&screen).contains("hostname []>") {
			// SAFETY: the live child id is a process id, and SIGINT is valid.
			assert_eq!(
				unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
				0
			);
			signalled = true;
		}
	}
	let output = child.wait_with_output().unwrap();
	assert!(output.stdout.is_empty());
	(
		output.status,
		String::from_utf8_lossy(&screen).replace("\r\n", "\n"),
	)
}

fn answers(root: &Path, confirm: &str) -> String {
	format!(
		"manual\nmail.example.org\nexample.org\n\nnone\nnone\n{}\n{}\n{}epistle:dev\n{confirm}\n",
		root.join("data").display(),
		root.join("etc/mail.toml").display(),
		"\n".repeat(7)
	)
}

/// Write the private draft the guided flow would have left behind, with
/// `config_path` carrying the escape sequence the review injected.
fn draft_with_an_escaped_config_path(root: &Path) {
	use std::os::unix::fs::PermissionsExt;
	let state = root.join("state/epistle");
	std::fs::create_dir_all(&state).expect("state dir");
	std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
	let draft = serde_json::json!({
		"mode": "manual",
		"hostname": "mail.example.org",
		"domains": "example.org",
		"data_dir": root.join("data").display().to_string(),
		"config_path": "/etc/epistle/\u{1b}[2Jmail.toml",
	});
	let file = state.join("init-draft.json");
	std::fs::write(&file, draft.to_string()).expect("write draft");
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod file");
}

#[test]
fn declining_the_review_creates_no_setup_files() {
	let dir = tempfile::tempdir().unwrap();
	let (status, text) = terminal(dir.path(), &answers(dir.path(), "no"), false, false);
	assert!(
		!dir.path().join("data").exists(),
		"declining confirmation must not create data"
	);
	assert!(
		!dir.path().join("etc").exists(),
		"declining confirmation must not create configuration"
	);
	assert!(status.success(), "{text}");
	assert!(text.contains("Setup review:"));
	assert!(text.contains("Apply this setup?"));
	assert!(text.contains("aborted: nothing was written"));
	assert!(!text.contains('\u{1b}'));
}

#[test]
fn confirmation_applies_setup_and_prints_locations_and_next_commands() {
	let dir = tempfile::tempdir().unwrap();
	let (status, text) = terminal(dir.path(), &answers(dir.path(), "yes"), false, false);
	assert!(status.success(), "{text}");
	assert!(dir.path().join("etc/mail.toml").is_file());
	assert!(dir.path().join("data/keys").is_dir());
	assert!(text.contains("Setup completed."));
	assert!(text.contains("epistle config-check"));
	assert!(text.contains("epistle stack up"));
	assert!(text.contains("epistle verify-dns"));
	assert!(!dir.path().join("state/epistle/init-draft.json").exists());
	println!("{text}");
}

#[test]
fn sigint_preserves_a_draft_and_a_new_process_offers_to_resume() {
	let dir = tempfile::tempdir().unwrap();
	let (status, _) = terminal(dir.path(), "manual\n", true, false);
	assert_eq!(status.signal(), Some(libc::SIGINT));
	let file = dir.path().join("state/epistle/init-draft.json");
	let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
	assert_eq!(saved["mode"], "manual");
	assert!(saved.get("hostname").is_none());
	let remaining = answers(dir.path(), "no");
	let remaining = remaining.strip_prefix("manual\n").unwrap();
	let (status, text) = terminal(dir.path(), &format!("yes\n{remaining}"), false, false);
	assert!(status.success(), "{text}");
	assert!(text.contains("Resume the saved init draft?"));
	assert!(text.contains("Apply this setup?"));
	assert!(!dir.path().join("etc").exists());
}

#[test]
fn invalid_entries_retry_in_the_real_terminal_before_confirmation() {
	let dir = tempfile::tempdir().unwrap();
	let input = answers(dir.path(), "yes")
		.replacen("mail.example.org\n", "bad hostname\nmail.example.org\n", 1)
		.replacen(
			"\nexample.org\n",
			"\nmail.example.org\nexample.org, example.org\nexample.org\n",
			1,
		)
		.replacen(
			&format!("{}\n", dir.path().join("data").display()),
			&format!("relative\n{}\n", dir.path().join("data").display()),
			1,
		);
	let (status, text) = terminal(dir.path(), &input, false, false);
	assert!(status.success(), "{text}");
	assert!(text.contains("bad hostname: must be a valid FQDN"));
	assert!(text.contains("relative: must be an absolute path"));
	assert!(dir.path().join("etc/mail.toml").is_file());
	println!("{text}");
}

/// A `config_path` written into the draft by another process can carry an
/// escape sequence. The run answers on a terminal with colour enabled, so an
/// escape that reached the stream would reach the screen instead of being
/// filtered out with the colour codes: the refused path is asked again, the
/// plan shows the plain path, and the screen never carries the sequence.
#[test]
fn a_draft_path_with_a_control_sequence_never_reaches_the_terminal() {
	let dir = tempfile::tempdir().unwrap();
	draft_with_an_escaped_config_path(dir.path());
	// Resume the draft, let the refused path be asked again, then decline.
	let input = format!(
		"yes\n\nnone\nnone\n{}\n{}epistle:dev\nno\n",
		dir.path().join("etc/mail.toml").display(),
		"\n".repeat(7),
	);
	let (status, text) = terminal(dir.path(), &input, false, true);
	assert!(status.success(), "{text}");
	assert!(text.contains("Resume the saved init draft?"), "{text}");
	assert!(
		!text.contains("\u{1b}[2J"),
		"the clear-screen sequence reached the screen"
	);
	assert!(
		text.contains("must not contain control characters"),
		"{text}"
	);
	assert!(text.contains("config: write "), "{text}");
	assert!(!dir.path().join("etc/mail.toml").exists(), "{text}");
	println!("{text}");
}

/// Answer the guided questions one prompt at a time on a real pseudo-terminal:
/// each answer is written only after its prompt has been read, which is when
/// a terminal has already decided whether to echo it. `interrupt_at` sends
/// SIGINT once that text appears.
fn terminal_stepwise(
	root: &Path,
	steps: &[(&str, &str)],
	interrupt_at: &str,
) -> (ExitStatus, String) {
	let (mut master, mut child) = spawn_on_terminal(root, false);
	let deadline = Instant::now() + DEADLINE;
	let mut screen = Vec::new();
	let mut gone = None;
	let mut answered = 0;
	let mut signalled = false;
	loop {
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			panic!("guided setup did not finish before its test deadline: {screen:?}");
		}
		if orphaned_terminal(&mut child, &mut gone) {
			panic!(
				"the pseudo-terminal stayed open after epistle init exited, so a process outside this test holds it"
			);
		}
		let mut poll = libc::pollfd {
			fd: master.as_raw_fd(),
			events: libc::POLLIN,
			revents: 0,
		};
		// SAFETY: poll points to one live descriptor record.
		let ready = unsafe { libc::poll(&mut poll, 1, 50) };
		assert!(ready >= 0);
		if ready > 0 {
			let mut buffer = [0u8; 4096];
			match master.read(&mut buffer) {
				Ok(0) | Err(_) => break,
				Ok(n) => screen.extend_from_slice(&buffer[..n]),
			}
		}
		let text = String::from_utf8_lossy(&screen).replace("\r\n", "\n");
		while answered < steps.len() && text.contains(steps[answered].0) {
			master
				.write_all(format!("{}\n", steps[answered].1).as_bytes())
				.unwrap();
			answered += 1;
		}
		if !signalled && text.contains(interrupt_at) {
			// SAFETY: the live child id is a process id, and SIGINT is valid.
			assert_eq!(
				unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
				0
			);
			signalled = true;
		}
	}
	let output = child.wait_with_output().unwrap();
	assert!(output.stdout.is_empty());
	(
		output.status,
		String::from_utf8_lossy(&screen).replace("\r\n", "\n"),
	)
}

#[test]
fn a_pasted_dns_credential_is_never_echoed_by_the_terminal() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	let steps = [
		("mode [manual]", "2"),
		("hostname []>", "mail.example.org"),
		("domains []>", "example.org"),
		("address []>", ""),
		("public IPv4", "none"),
		("public IPv6", "none"),
		("data_dir [", &root.join("data").display().to_string()),
		(
			"config_path [",
			&root.join("etc/mail.toml").display().to_string(),
		),
		("DNS provider [", ""),
		("DNS zone [", ""),
		("DNS credential source [", "2"),
		("DNS credential reference", "TOKEN=private-value"),
		("Invalid credential reference", "EPISTLE_DNS_TOKEN"),
	];
	let (status, text) = terminal_stepwise(root, &steps, "IMAP [");
	assert_eq!(status.signal(), Some(libc::SIGINT), "{text}");
	assert!(text.contains("Invalid credential reference"), "{text}");
	assert!(!text.contains("private-value"), "{text}");
	assert!(!text.contains("TOKEN="), "{text}");
	assert!(text.contains("EPISTLE_DNS_TOKEN"), "{text}");
	assert!(!root.join("etc").exists(), "{text}");
	println!("{text}");
}
