//! The list commands on a terminal: a bold header, the state column with
//! its symbol, every row inside the width. The plain form each list printed
//! before is pinned by the command's own tests and stays as it was.

use std::collections::BTreeMap;
use std::process::ExitCode;

use crate::cli::term::table::tests::base::visible;
use crate::cli::term::{Decor, fake};
use crate::config::Config;

fn config(dir: &std::path::Path, extra: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\", \"example.net\"]\n\
		 [[listeners]]\nkind = \"smtp\"\naddr = \"127.0.0.1\"\nport = 2525\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\", \"postmaster@example.org\"]\n{extra}",
		dir
	);
	toml::from_str(&toml).expect("config parses")
}

const ALIASES: &str = "[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n\
	[[alias]]\naddress = \"sales-and-partnerships-for-the-long-name@example.net\"\nmembers = [\"alice@example.org\"]\n";

/// Run `body` against a fake terminal of `width` and return what it wrote,
/// line by line, with the escapes left in.
fn on_terminal(width: usize, body: impl FnOnce(&mut Vec<u8>)) -> Vec<String> {
	let mut out = Vec::new();
	fake::with_stdout(Decor::coloured(width), || body(&mut out));
	String::from_utf8(out)
		.expect("utf-8")
		.lines()
		.map(str::to_string)
		.collect()
}

fn assert_fits(lines: &[String], width: usize) {
	for line in lines {
		let seen = visible(line);
		assert!(seen.chars().count() <= width, "{width}: {seen:?}");
	}
}

#[test]
fn account_list_shows_each_account_enabled_with_its_source() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let lines = on_terminal(120, |out| {
		assert_eq!(crate::cli::accounts::list(&config, out), ExitCode::SUCCESS);
	});
	assert!(lines[0].starts_with("\x1b[1mNAME"), "{lines:#?}");
	assert_eq!(
		visible(&lines[1]),
		"alice  ✔ enabled  static  alice@example.org,postmaster@example.org"
	);
	assert!(lines[1].contains("\x1b[32m✔ enabled"), "{lines:#?}");
	assert_eq!(lines.last().map(String::as_str), Some("1 accounts"));
	let narrow = on_terminal(40, |out| {
		crate::cli::accounts::list(&config, out);
	});
	assert_fits(&narrow, 40);
}

#[test]
fn alias_list_keeps_the_state_column_aligned_when_the_terminal_is_narrow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), ALIASES);
	let lines = on_terminal(40, |out| {
		crate::cli::alias::list(&config, false, out).expect("list");
	});
	assert_eq!(lines.len(), 3, "{lines:#?}");
	assert_fits(&lines, 40);
	let at = |line: &str| visible(line).chars().position(|c| c == '✔');
	assert!(
		at(&lines[1]).is_some(),
		"the state is on screen: {lines:#?}"
	);
	assert_eq!(at(&lines[1]), at(&lines[2]), "{lines:#?}");
	assert!(visible(&lines[2]).contains('…'), "{lines:#?}");
}

#[test]
fn service_list_marks_enabled_and_disabled_services() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let lines = on_terminal(120, |out| {
		crate::cli::service::list(&config, false, out).expect("list");
	});
	let smtp = lines
		.iter()
		.map(|line| visible(line))
		.find(|line| line.starts_with("smtp "))
		.expect("smtp row");
	assert!(smtp.contains("✔ enabled"), "{smtp:?}");
	assert!(
		lines.iter().any(|line| line.contains("\x1b[2m✘ disabled")),
		"a disabled service is dimmed: {lines:#?}"
	);
}

#[test]
fn domain_list_is_aligned_under_a_bold_header() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let lines = on_terminal(120, |out| {
		crate::cli::domain::list(&config, false, out).expect("list");
	});
	assert_eq!(
		lines.iter().map(|line| visible(line)).collect::<Vec<_>>(),
		[
			"DOMAIN       ALIASES TO  ALIASES FROM",
			"example.org  -           -",
			"example.net  -           -",
		]
	);
	assert!(lines[0].starts_with("\x1b[1m"), "{lines:#?}");
}

#[test]
fn json_is_never_decorated() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), ALIASES);
	let lines = on_terminal(120, |out| {
		crate::cli::alias::list(&config, true, out).expect("list");
		crate::cli::domain::list(&config, true, out).expect("list");
		crate::cli::service::list(&config, true, out).expect("list");
	});
	for line in &lines {
		assert!(!line.contains('\x1b') && !line.contains('✔'), "{line:?}");
	}
}

#[test]
fn queue_list_marks_a_held_message() {
	use crate::smtp::session::AcceptedMessage;
	use crate::storage::FsSpool;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	spool
		.update_envelope(id, |envelope| envelope.hold(1_700_000_000))
		.expect("hold");
	let lines = on_terminal(120, |out| {
		assert_eq!(
			crate::cli::queue::list(dir.path(), None, out),
			ExitCode::SUCCESS
		);
	});
	assert!(lines[0].starts_with("\x1b[1mID"), "{lines:#?}");
	assert!(lines[1].contains("\x1b[33m⚠ held"), "{lines:#?}");
	assert!(
		visible(&lines[1]).contains("alice@example.org"),
		"{lines:#?}"
	);
	assert_eq!(lines.last().map(String::as_str), Some("1 queued"));
}

#[test]
fn masked_list_marks_enabled_addresses() {
	use crate::cli::masked::MaskedCli;
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let added = crate::cli::masked::run(
		&config,
		MaskedCli::Add {
			account: "alice".into(),
			label: "shop".into(),
			domain: None,
		},
		false,
		1_700_000_000,
		&mut out,
		&mut err,
	);
	assert_eq!(
		added,
		ExitCode::SUCCESS,
		"{}",
		String::from_utf8_lossy(&err)
	);
	let lines = on_terminal(120, |out| {
		let mut err = Vec::new();
		let listed = crate::cli::masked::run(
			&config,
			MaskedCli::List {
				account: "alice".into(),
				json: false,
			},
			false,
			1_700_000_000,
			out,
			&mut err,
		);
		assert_eq!(listed, ExitCode::SUCCESS);
	});
	assert!(lines[0].starts_with("\x1b[1mADDRESS"), "{lines:#?}");
	assert!(lines[1].contains("\x1b[32m✔ enabled"), "{lines:#?}");
	assert!(visible(&lines[1]).contains("shop"), "{lines:#?}");
}

#[test]
fn probe_marks_each_listener_and_keeps_the_plain_lines_off_a_terminal() {
	use crate::cli::probe::{ProbeLine, render};
	let lines = [
		ProbeLine {
			kind: "smtp",
			addr: "127.0.0.1:25".into(),
			ok: true,
			error: None,
			warning: None,
		},
		ProbeLine {
			kind: "imaps",
			addr: "127.0.0.1:993".into(),
			ok: false,
			error: Some("connect: connection refused".into()),
			warning: None,
		},
	];
	let mut plain = Vec::new();
	render(&lines, false, &mut plain);
	assert_eq!(
		String::from_utf8(plain).expect("utf-8"),
		"ok smtp 127.0.0.1:25\nfail imaps 127.0.0.1:993: connect: connection refused\n"
	);
	let drawn = on_terminal(120, |out| render(&lines, false, out));
	assert_eq!(
		drawn.iter().map(|line| visible(line)).collect::<Vec<_>>(),
		[
			"STATE   SERVICE  ADDRESS        DETAIL",
			"✔ ok    smtp     127.0.0.1:25",
			"✘ fail  imaps    127.0.0.1:993  connect: connection refused",
		]
	);
	assert!(drawn[2].contains("\x1b[31m✘ fail"), "{drawn:#?}");
	let json = on_terminal(120, |out| render(&lines, true, out));
	assert!(json.iter().all(|line| !line.contains('\x1b')), "{json:#?}");
}

#[test]
fn probe_draws_an_uncheckable_listener_as_a_warning() {
	let lines = [crate::cli::probe::ProbeLine {
		kind: "api",
		addr: "0.0.0.0:8025".into(),
		ok: false,
		error: None,
		warning: Some("not checkable from here".into()),
	}];
	let drawn = on_terminal(120, |out| crate::cli::probe::render(&lines, false, out));
	assert!(visible(&drawn[1]).contains("warn"), "{drawn:?}");
	assert!(visible(&drawn[1]).contains("not checkable from here"));
	assert!(!visible(&drawn[1]).contains("fail"));
}
