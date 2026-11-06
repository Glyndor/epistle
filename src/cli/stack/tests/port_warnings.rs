//! Unit tests for the podup warning filter.
//!
//! The integration coverage in `tests/cli/stack/stack_port_warnings.rs`
//! drives the real binary against a stub `podup` that prints the
//! warnings; this file stays inside the module, so the shape of the
//! warning podup prints and the rule that decides which ports the stack
//! publishes on purpose are checked without a child process.

use super::super::port_warnings::Published;
use crate::config::Config;

/// The warning podup prints for a port published on every interface.
fn warning(port: u16) -> String {
	format!(
		"podup: warning: service 'mail': port {port} is published on every interface; \
		 use \"127.0.0.1:{port}:{port}\" to keep it on the host\n"
	)
}

/// A configuration with the given `[[listeners]]` entries, as the stack
/// reads it: the bind address of each listener is what tells a public
/// publication from one nobody asked for.
fn config_with(listeners: &str) -> Config {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\
		 \n[tls]\ncert_file = \"/var/lib/epistle/keys/cert.pem\"\nkey_file = \"/var/lib/epistle/keys/key.pem\"\n{listeners}",
		dir.path()
	);
	std::fs::write(&path, body).expect("write config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		// The loader refuses a config anybody else can read.
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0600 on config");
	}
	Config::load(&path).expect("config loads")
}

/// A listener on the wildcard, the way `init` writes every mail listener.
const WILDCARD: &str = "\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n";
/// A listener on loopback, which no publication reaches from the host.
const LOOPBACK: &str = "\n[[listeners]]\nkind = \"metrics\"\naddr = \"127.0.0.1\"\nport = 9090\n";

/// The warning about a port the stack publishes on purpose is not
/// printed: the note replaces it.
#[test]
fn the_warning_about_a_wildcard_port_becomes_the_note() {
	let config = config_with(WILDCARD);
	let mut published = Published::new(&config);
	let mut out: Vec<u8> = Vec::new();
	published.line(warning(25).as_bytes(), &mut out);
	assert!(
		out.is_empty(),
		"the warning about a port the stack publishes on purpose must not reach the operator; got {out:?}"
	);
	let mut note: Vec<u8> = Vec::new();
	published.note(&mut note);
	assert_eq!(
		String::from_utf8_lossy(&note),
		"note: port 25 is public on purpose (bind 0.0.0.0); podup warns about it and it is expected\n",
		"the note names the port and the bind that makes it public"
	);
}

/// The warning about a port the stack does not publish on purpose stays
/// exactly as podup printed it: that one is about a port nobody asked to
/// reach the public internet.
#[test]
fn the_warning_about_a_loopback_port_is_kept() {
	let config = config_with(LOOPBACK);
	let mut published = Published::new(&config);
	let mut out: Vec<u8> = Vec::new();
	published.line(warning(9090).as_bytes(), &mut out);
	assert_eq!(
		String::from_utf8_lossy(&out),
		warning(9090),
		"the warning must stay exactly as podup printed it"
	);
	let mut note: Vec<u8> = Vec::new();
	published.note(&mut note);
	assert!(
		note.is_empty(),
		"no warning was replaced, so there is no note; got {note:?}"
	);
}

/// A line that is not a warning about a published port is never touched.
#[test]
fn a_line_that_is_not_a_warning_is_kept() {
	let config = config_with(WILDCARD);
	let mut published = Published::new(&config);
	let mut out: Vec<u8> = Vec::new();
	let line = "podup: creating container epistle-mail-1\n";
	published.line(line.as_bytes(), &mut out);
	assert_eq!(
		String::from_utf8_lossy(&out),
		line,
		"every line podup printed that is not a warning stays as it is"
	);
}

/// A warning of another shape names no port, so it stays as it is: the
/// filter replaces the one warning podup prints and nothing else.
#[test]
fn a_warning_of_another_shape_is_kept() {
	let config = config_with(WILDCARD);
	let mut published = Published::new(&config);
	let mut out: Vec<u8> = Vec::new();
	let line = "podup: warning: service 'mail': the image is older than the compose file\n";
	published.line(line.as_bytes(), &mut out);
	assert_eq!(
		String::from_utf8_lossy(&out),
		line,
		"a warning that is not about a published port stays as it is"
	);
}

/// The note names every port the stack publishes on purpose and the
/// wildcard they bind, and it is one line however many there are.
#[test]
fn the_note_names_every_port_the_stack_publishes_on_purpose() {
	let config = config_with(
		"\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\n\
		 \n[[listeners]]\nkind = \"imap\"\naddr = \"0.0.0.0\"\n\
		 \n[[listeners]]\nkind = \"imaps\"\naddr = \"0.0.0.0\"\n",
	);
	let mut published = Published::new(&config);
	let mut out: Vec<u8> = Vec::new();
	for port in [25, 143, 993] {
		published.line(warning(port).as_bytes(), &mut out);
	}
	assert!(out.is_empty(), "every warning was replaced; got {out:?}");
	let mut note: Vec<u8> = Vec::new();
	published.note(&mut note);
	assert_eq!(
		String::from_utf8_lossy(&note),
		"note: ports 25, 143, 993 are public on purpose (bind 0.0.0.0); podup warns about them and it is expected\n",
		"the note is one line that names every port and the bind"
	);
}
