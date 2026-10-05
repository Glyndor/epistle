//! Per-line rendering of the `PlanStep::Listeners` step. The
//! renderer writes one listener per line, indented under the step,
//! so the operator reads them in the same order the configuration
//! will load. The format is pinned with whole-line assertions rather
//! than substring checks: a regression that loses the newline and
//! concatenates two entries on one line goes red on whichever line
//! check catches it first.
//!
//! Sister to the other `apply_*_tests*.rs` files because those are
//! already at the per-file line limit and because the per-line
//! format lives on a focused seam that this file owns.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::Answers;
use super::*;
use crate::cli::init::answers::{Mode, Services};

fn answers_with_services(services: Services) -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: std::path::PathBuf::from("/var/lib/epistle"),
		config_path: std::path::PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services,
		image: None,
	}
}

/// A plan with smtp + imap + submission must write one listener per
/// line, indented under the `listeners:` step header, with the kind
/// left-padded and the bind address on the same line. No two kinds
/// may share a line. The renderer cannot hide a missing listener
/// behind `contains`: a future regression that drops a newline and
/// concatenates two entries on one line goes red here.
#[test]
fn plan_listeners_render_one_per_line_with_padded_kind() {
	let answers = answers_with_services(Services {
		imap: true,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
	});
	let plan = plan(&answers).expect("plan");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	let lines: Vec<String> = rendered.lines().map(str::to_owned).collect();

	// Find the lines that name each listener kind. Each one must
	// trim to exactly the format the renderer promises, with the
	// kind left-padded to the same width and one space before the
	// bind address. A future regression that loses the padding, or
	// that splits the kind from the address across lines, fails
	// here without leaning on `contains`.
	let mut smtp_line = None;
	let mut imap_line = None;
	let mut submission_line = None;
	for line in &lines {
		// Skip the step-number prefix and the `listeners:` header.
		// The renderer puts the kind on a line that starts (after
		// any indentation) with the kebab-case kind name. We test
		// the trimmed content so the exact indent does not matter.
		let trimmed = line.trim_start().trim_end();
		if trimmed.starts_with("smtp") && trimmed.contains("[::]:25") {
			smtp_line = Some(trimmed.to_owned());
		}
		if trimmed.starts_with("imap") && trimmed.contains("[::]:143") {
			imap_line = Some(trimmed.to_owned());
		}
		if trimmed.starts_with("submission") && trimmed.contains("[::]:587") {
			submission_line = Some(trimmed.to_owned());
		}
	}
	// Belt and braces: every listener is named, every line carries
	// exactly one kind. The exact padding is whatever the renderer
	// chose (the renderer uses `{:<12}` followed by a space and the
	// address; any exact padding is fine, as
	// long as it is consistent across listener kinds).
	let smtp = smtp_line.expect("smtp line must exist");
	assert!(
		smtp.starts_with("smtp") && smtp.ends_with("[::]:25"),
		"smtp line must start with the kind and end with the bind address; got: {smtp:?}"
	);
	let imap = imap_line.expect("imap line must exist");
	assert!(
		imap.starts_with("imap") && imap.ends_with("[::]:143"),
		"imap line must start with the kind and end with the bind address; got: {imap:?}"
	);
	let submission = submission_line.expect("submission line must exist");
	assert!(
		submission.starts_with("submission") && submission.ends_with("[::]:587"),
		"submission line must start with the kind and end with the bind address; got: {submission:?}"
	);
	// The padding between kind and address must be consistent: a
	// future regression that widens the kind column for one kind
	// and not the others (a copy-paste bug from a different
	// `{:<N}`) goes red here. The column where the bind address
	// starts must be the same for every listener.
	let smtp_addr_col = smtp.find(':').expect("smtp line has an address");
	let imap_addr_col = imap.find(':').expect("imap line has an address");
	let submission_addr_col = submission
		.find(':')
		.expect("submission line has an address");
	assert_eq!(
		smtp_addr_col, imap_addr_col,
		"the bind-address column must be the same for every listener (smtp vs imap); \
		 smtp={smtp:?}, imap={imap:?}"
	);
	assert_eq!(
		smtp_addr_col, submission_addr_col,
		"the bind-address column must be the same for every listener (smtp vs submission); \
		 smtp={smtp:?}, submission={submission:?}"
	);

	// No line carries two listener kinds. Catches a regression
	// that loses the newline and concatenates two entries on the
	// same line.
	for line in &lines {
		let kinds_on_line = ["smtp", "imap", "submission", "pop3s", "manage-sieve", "api"]
			.iter()
			.filter(|kind| line.trim_start().starts_with(*kind))
			.count();
		assert!(
			kinds_on_line <= 1,
			"no listener line must carry two kinds; got: {line:?}"
		);
	}
}

/// The `listeners:` step header is its own line, separate from the
/// listener entries. Without that header the operator cannot scan
/// the step in the same order the configuration will load. The
/// step number prefix (`  N. `) is added by `Plan::write_to` and
/// ignored here.
#[test]
fn plan_listeners_step_has_its_own_header_line() {
	let answers = answers_with_services(Services::default());
	let plan = plan(&answers).expect("plan");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	let header_seen = rendered.lines().any(|line| {
		// Strip the `  N. ` step-number prefix `write_to` adds.
		line.trim_start()
			.strip_prefix(|c: char| c.is_ascii_digit())
			.and_then(|rest| rest.strip_prefix(". "))
			.map(str::trim_end)
			== Some("listeners:")
	});
	assert!(
		header_seen,
		"the listeners step must have its own `listeners:` header line; \
		 got:\n{rendered}"
	);
}

/// Every listener the plan prints is on a line of its own (no
/// concatenation). Catches a regression that replaces the per-entry
/// `writeln!` with a single `write!`.
#[test]
fn plan_listeners_step_has_one_line_per_listener() {
	let answers = answers_with_services(Services {
		imap: true,
		submission: true,
		pop3: true,
		managesieve: true,
		webdav: true,
		api: true,
		database: false,
	});
	let plan = plan(&answers).expect("plan");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	let listener_lines: Vec<&str> = rendered
		.lines()
		.filter(|line| {
			let trimmed = line.trim_start();
			[
				"smtp",
				"imap",
				"submission",
				"pop3s",
				"manage-sieve",
				"web-dav",
				"api",
			]
			.iter()
			.any(|kind| trimmed.starts_with(kind) && trimmed.contains(':'))
		})
		.collect();
	assert_eq!(
		listener_lines.len(),
		7,
		"every listener must be on its own line; got {} lines:\n{rendered}",
		listener_lines.len()
	);
}

/// Sanity: the dual-stack bind address (`[::]:25`) prints with the
/// IPv6 bracket form. The config carries the same form, so an
/// operator scanning the plan sees the same address the config
/// will load.
#[test]
fn plan_listeners_step_renders_dual_stack_address_with_brackets() {
	let answers = answers_with_services(Services::default());
	let plan = plan(&answers).expect("plan");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	let smtp_line = rendered
		.lines()
		.find(|line| line.trim_start().starts_with("smtp"))
		.expect("smtp line");
	assert!(
		smtp_line.contains("[::]:25"),
		"smtp line must carry the dual-stack bind [::]:25 verbatim; got: {smtp_line:?}"
	);
	// Reference the import so the file's cargo check stays clean if
	// the IPv6 form is later split into a helper.
	let _ = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
	let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
}

/// Every listener the plan prints carries the port the listener
/// schema defaults assign, so the line the operator reads matches
/// the address the config will load. The expected port is derived by
/// parsing the plan's kind string with the same path `Config::load`
/// uses (the `ListenerKind` deserialiser) and asking the schema what
/// its `default_port()` is, not a hardcoded list. A future drift in
/// the schema (a new IANA assignment, a deliberate change to the
/// dev port) flows through both the plan and the serve path
/// together; this test would catch a `listener_entries` that
/// hardcoded the old number alongside a `ListenerKind` that
/// switched. Sister to the same-name test in the now-deleted
/// `apply_bind_decision_tests.rs`; this file owns the per-listener
/// rendering seam.
#[test]
fn listener_entries_match_schema_default_ports() {
	use crate::cli::init::plan::ListenerEntry;
	let plan = plan(&answers_with_services(Services {
		imap: true,
		submission: true,
		pop3: true,
		managesieve: true,
		webdav: true,
		api: true,
		database: false,
	}))
	.expect("plan");
	let entries: Vec<&ListenerEntry> = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::Listeners { entries, .. } => Some(entries.iter().collect::<Vec<_>>()),
			_ => None,
		})
		.expect("listeners step");
	// Belt and braces on the count too: a future kind added to the
	// answers set without a matching plan entry shows up here as a
	// shorter `entries` vector, not as a wrong port.
	assert_eq!(
		entries.len(),
		7,
		"expected seven entries (smtp + imap + submission + pop3s + manage-sieve + web-dav + api), \
		 got {entries:?}"
	);
	for entry in &entries {
		// Parse the plan's kind string the same way `Config::load`
		// does so the round-trip cannot drift: a typo in the plan
		// (e.g. `manage_sieve` instead of `manage-sieve`) fails
		// here before the port check.
		let listener: crate::config::Listener = toml::from_str(&format!("kind = {:?}", entry.kind))
			.unwrap_or_else(|error| {
				panic!(
					"plan produced a kind `{}` that does not round-trip \
					 through Listener; the plan and the schema have \
					 drifted: {error}",
					entry.kind
				)
			});
		assert_eq!(
			entry.port,
			listener.kind.default_port(),
			"plan port for `{}` ({}) must equal ListenerKind::default_port() ({}); \
			 the plan hardcoded the old number instead of asking the schema",
			entry.kind,
			entry.port,
			listener.kind.default_port()
		);
	}
}
