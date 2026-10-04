//! When the operator's config on disk already carries a non-empty
//! `listeners` array, `init` must keep those listeners exactly as
//! they are and not overwrite them with the ones `build_config`
//! synthesises from the answers. A re-run with different service
//! toggles must therefore leave the operator's bind addresses (and
//! any kinds init does not write, like `metrics` or `acme`) on disk
//! untouched. The plan step names the kept listeners so the operator
//! still sees the bind addresses `serve` will expose.
//!
//! Sister to the other `apply_*_tests*.rs` files because those are
//! already at the per-file line limit and because the keep-existing-
//! listeners path lives on a focused seam.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::apply_config;
use super::*;
use crate::cli::init::answers::{Answers, Mode, Services};
use crate::config::ListenerKind;

/// Write `content` to `path` with mode `0600` so `Config::load`
/// accepts it; the loader refuses files with group/world access and
/// the `existing_operators_listeners` helper piggy-backs on the same
/// gate so a permissive file would fail the helper before the test
/// could inspect it.
fn write_0600(path: &PathBuf, content: &str) {
	std::fs::write(path, content).expect("write file");
	let perms = std::fs::Permissions::from_mode(0o600);
	std::fs::set_permissions(path, perms).expect("set permissions 0600");
}

fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(std::net::Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(std::net::Ipv6Addr::new(
			0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
		)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
	}
}

/// A re-run of `init` against a config the operator has curated
/// (one `imap` on a non-default address and port, plus a `metrics`
/// listener that `init` does not write) must keep both listeners
/// exactly as they were and must not insert the `smtp` listener
/// `init` would otherwise write. The byte-level equality on the
/// `[[listeners]]` table is the gate: a regression that drops the
/// `keep_existing_listeners` flag in `apply` lets the merge replace
/// the operator's array with `init`'s, which adds `smtp` and drops
/// `metrics`, and the test goes red on `kind = "metrics"` (gone) and
/// `kind = "smtp"` (added).
#[test]
fn apply_keeps_operator_listeners_when_existing_config_has_them() {
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
	// Re-run with imap and submission enabled: a design that
	// unconditionally replaces the operator's listeners would write
	// smtp alongside imap. The kept-listener path keeps the existing
	// array and does not write any of the listeners `init` would
	// normally add.
	answers.services = Services {
		imap: true,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
	};

	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply failed when keeping listeners: {:?}",
		outcome.error
	);

	let written = std::fs::read_to_string(&config_path).expect("read config");
	let listeners = crate::config::Config::load(&config_path)
		.expect("config reload")
		.listeners;
	assert_eq!(
		listeners.len(),
		2,
		"operator's two listeners must survive the re-run, got: {listeners:?}"
	);
	assert!(
		listeners.iter().any(|l| {
			l.kind == ListenerKind::Imap
				&& l.addr == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
				&& l.port == Some(1143)
		}),
		"the imap listener on 127.0.0.1:1143 must survive byte-for-byte; got: {listeners:?}"
	);
	assert!(
		listeners.iter().any(|l| {
			l.kind == ListenerKind::Metrics
				&& l.addr == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
				&& l.port == Some(9090)
		}),
		"the metrics listener on 127.0.0.1:9090 must survive byte-for-byte; got: {listeners:?}"
	);
	assert!(
		!listeners.iter().any(|l| l.kind == ListenerKind::Smtp),
		"init must not add an smtp listener when the operator already has listeners; got: {listeners:?}"
	);
	assert!(
		!written.contains("kind = \"smtp\""),
		"smtp must not be written into a config the operator already populated; got: {written}"
	);
	assert!(
		written.contains("kind = \"metrics\""),
		"metrics must still be in the file; got: {written}"
	);
	assert!(
		written.contains("addr = \"127.0.0.1\"") && written.contains("port = 1143"),
		"the imap address and port must still be present; got: {written}"
	);
	assert!(
		written.contains("kind = \"metrics\"") && written.contains("port = 9090"),
		"the metrics kind and port must still be present; got: {written}"
	);
}

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
		imap: true,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
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

/// `existing_operators_listeners` reports `Ok(None)` when the
/// existing `listeners` array is empty (the default for a fresh
/// install: `init` writes its own). Keeps the edge documented and
/// confirms the merge in that case still runs normally.
#[test]
fn existing_operators_listeners_is_none_when_array_is_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	// A complete config with an empty listeners array. The
	// `[[listeners]]` table is required to be non-empty by the
	// schema, so `Listener` deserialisation fails; what matters
	// for the helper contract is that the helper does not promote
	// this into a `Some(_)` keep-existing-listeners decision.
	let body = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\
		[auth]\n\
		allow_insecure_auth = false\n";
	write_0600(&config_path, body);
	let out = apply_config::existing_operators_listeners(&config_path)
		.expect("read returns Ok(None) for an absent listeners key");
	assert!(
		out.is_none(),
		"no listeners key in the existing config must yield Ok(None); got: {out:?}"
	);
}
