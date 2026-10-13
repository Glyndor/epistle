//! The binary on a real pseudo-terminal: a list is drawn with symbols and
//! colour, and with `NO_COLOR`, `TERM=dumb` or `--json` the terminal gets
//! exactly the bytes a pipe gets. Run through `CARGO_BIN_EXE_epistle`, so
//! what is checked is the decision the shipped binary makes.

#![cfg(unix)]

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn config(dir: &Path) -> String {
	let path = dir.join("mail.toml");
	std::fs::create_dir(dir.join("data")).expect("data dir");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\
			 [[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n",
			dir.join("data")
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path.to_string_lossy().into_owned()
}

/// Run `args` with `env` set, stdout and stderr on one pseudo-terminal of
/// 100 columns; returns what the terminal received, `\r\n` read as `\n`.
fn on_pty(args: &[&str], env: &[(&str, &str)]) -> String {
	on_pty_with(args, env, false)
}

/// [`on_pty`], with stdin on the terminal too when `stdin_tty` is set.
fn on_pty_with(args: &[&str], env: &[(&str, &str)], stdin_tty: bool) -> String {
	let size = libc::winsize {
		ws_row: 24,
		ws_col: 100,
		ws_xpixel: 0,
		ws_ypixel: 0,
	};
	let (mut master, mut slave) = (-1, -1);
	// SAFETY: both out pointers are valid; the name may be null.
	let rc = unsafe {
		libc::openpty(
			&mut master,
			&mut slave,
			std::ptr::null_mut(),
			std::ptr::null(),
			&size,
		)
	};
	assert_eq!(rc, 0, "openpty");
	// SAFETY: openpty returned two fresh descriptors owned from here on.
	let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
	let mut command = Command::new(env!("CARGO_BIN_EXE_epistle"));
	command
		.args(args)
		.env_remove("NO_COLOR")
		.env_remove("CLICOLOR_FORCE")
		.env("TERM", "xterm-256color")
		.stdin(if stdin_tty {
			Stdio::from(slave.try_clone().expect("dup"))
		} else {
			Stdio::null()
		})
		.stdout(slave.try_clone().expect("dup"))
		.stderr(slave);
	for (key, value) in env {
		command.env(key, value);
	}
	let mut child = command.spawn().expect("spawn epistle");
	drop(command);
	let mut screen = Vec::new();
	let mut master = std::fs::File::from(master);
	let mut chunk = [0u8; 4096];
	// The read ends with EIO once the child has exited and closed the slave.
	while let Ok(n) = master.read(&mut chunk) {
		if n == 0 {
			break;
		}
		screen.extend_from_slice(&chunk[..n]);
	}
	child.wait().expect("wait");
	String::from_utf8_lossy(&screen).replace("\r\n", "\n")
}

/// The same command with stdout and stderr piped, as a script runs it.
fn piped(args: &[&str]) -> String {
	let output = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(args)
		.env_remove("NO_COLOR")
		.env_remove("CLICOLOR_FORCE")
		.stdin(Stdio::null())
		.output()
		.expect("run epistle");
	let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
	text.push_str(&String::from_utf8_lossy(&output.stderr));
	text
}

#[test]
fn a_terminal_gets_symbols_and_colour() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let screen = on_pty(&["alias", "--config", &config, "list"], &[]);
	assert!(screen.contains("\x1b[32m✔ enabled"), "{screen:?}");
	assert!(screen.starts_with("\x1b[1mADDRESS"), "{screen:?}");
}

#[test]
fn no_color_dumb_and_json_give_the_terminal_the_plain_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let list = ["alias", "--config", config.as_str(), "list"];
	let plain = piped(&list);
	assert!(plain.starts_with("ADDRESS "), "{plain:?}");
	assert_eq!(on_pty(&list, &[("NO_COLOR", "1")]), plain, "NO_COLOR");
	assert_eq!(on_pty(&list, &[("TERM", "dumb")]), plain, "TERM=dumb");
	let json = ["alias", "--config", config.as_str(), "list", "--json"];
	assert_eq!(on_pty(&json, &[]), piped(&json), "--json");
}

#[test]
fn no_color_keeps_the_spinner_and_the_hidden_cursor_away() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let verify = ["verify", "--config", config.as_str()];
	let screen = on_pty(&verify, &[("NO_COLOR", "1")]);
	assert_eq!(screen, piped(&verify));
	assert!(!screen.contains('\x1b'), "{screen:?}");
	let drawn = on_pty(&verify, &[]);
	assert!(
		drawn.contains("\x1b[?25l") && drawn.contains("\x1b[?25h"),
		"{drawn:?}"
	);
	assert!(drawn.contains("✔"), "{drawn:?}");
}

#[test]
fn a_missing_account_is_offered_on_a_terminal_and_not_with_no_color() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let show = ["account", "show", "--config", config.as_str()];
	let offered = on_pty_with(&show, &[], true);
	assert!(
		offered.starts_with("there is no account to pick from\n"),
		"{offered:?}"
	);
	let plain = piped(&show);
	assert!(
		plain.contains("required arguments were not provided"),
		"{plain:?}"
	);
	assert_eq!(on_pty_with(&show, &[("NO_COLOR", "1")], true), plain);
	assert_eq!(on_pty_with(&show, &[("TERM", "dumb")], true), plain);
}
