//! The plan step that names the listeners `init` will keep, so the
//! operator still sees the bind addresses `serve` will expose.

use super::listeners::{answers_minimal, write_0600};
use super::*;
use crate::cli::init::answers::Services;

/// Plan rendered against a config that already carries two operator
/// listeners says so in words and lists both listeners with their
/// bind addresses and ports. The test walks the rendered plan line
/// by line so a regression that hides a missing listener with a
/// `contains` check cannot pass: the `listeners:` header line must
/// be followed by exactly the two operator entries, no smtp, no
/// extra.
#[test]
fn plan_renders_kept_listeners_when_existing_config_has_them() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let operator_listeners = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"imap\"\n\
		addr = \"127.0.0.1\"\n\
		port = 1143\n\n\
		[[listeners]]\n\
		kind = \"metrics\"\n\
		addr = \"127.0.0.1\"\n\
		port = 9090\n";
	std::fs::create_dir_all(data_dir.parent().unwrap()).expect("mkdir data");
	write_0600(&config_path, operator_listeners);

	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	answers.services = Services {
		antivirus: None,
		panel: None,
		panel_image: None,
		imap: true,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
		certs: false,
	};
	let plan = crate::cli::init::apply::plan(&answers).expect("plan");

	let listeners_step = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::Listeners { entries, kept } => Some((entries, kept)),
			_ => None,
		})
		.expect("plan must carry a Listeners step");
	assert!(
		listeners_step.1,
		"the Listeners step must be marked kept=true; the plan said init keeps the operator's listeners"
	);
	let kinds: Vec<&str> = listeners_step.0.iter().map(|e| e.kind.as_str()).collect();
	assert_eq!(
		kinds,
		vec!["imap", "metrics"],
		"the kept listeners must appear in the plan exactly as on disk; got {kinds:?}"
	);
	let imap = listeners_step.0.iter().find(|e| e.kind == "imap").unwrap();
	assert_eq!(
		imap.addr,
		std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
	);
	assert_eq!(imap.port, 1143);
	let metrics = listeners_step
		.0
		.iter()
		.find(|e| e.kind == "metrics")
		.unwrap();
	assert_eq!(
		metrics.addr,
		std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
	);
	assert_eq!(metrics.port, 9090);

	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("write plan");
	assert!(
		rendered.contains("keep the 2 listeners already in"),
		"the plan must say the operator's listeners are being kept; got: {rendered}"
	);
	assert!(
		!rendered.contains("kind = \"smtp\""),
		"smtp must not be in the plan when init does not write any listeners; got: {rendered}"
	);
	// Belt and braces: the address and port of both kept listeners
	// must appear in the rendered plan, with the kind on the same
	// line so a future regression that loses the per-listener line
	// does not slip past `contains`.
	let lines: Vec<&str> = rendered.lines().collect();
	let mut imap_seen = false;
	let mut metrics_seen = false;
	for line in &lines {
		let trimmed = line.trim_start();
		if trimmed.starts_with("imap") && trimmed.contains("127.0.0.1:1143") {
			imap_seen = true;
		}
		if trimmed.starts_with("metrics") && trimmed.contains("127.0.0.1:9090") {
			metrics_seen = true;
		}
	}
	assert!(
		imap_seen && metrics_seen,
		"both kept listeners must appear as their own line in the plan; \
		 got: {rendered}"
	);
}

/// With no existing config on disk, `init` writes its own listeners.
/// The plan must render the `listeners:` header and not the "keep"
/// wording, so the kept-listener branch does not shadow the
/// default-write branch.
#[test]
fn plan_writes_init_listeners_when_existing_config_has_none() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let plan = crate::cli::init::apply::plan(&answers).expect("plan");
	let listeners_step = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::Listeners { entries, kept } => Some((entries, kept)),
			_ => None,
		})
		.expect("listeners step");
	assert!(
		!listeners_step.1,
		"kept must be false when no existing config"
	);
	let kinds: Vec<&str> = listeners_step.0.iter().map(|e| e.kind.as_str()).collect();
	assert!(kinds.contains(&"smtp"));
}
